from __future__ import annotations

import time
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Count, Q

from control.models import ClientAccess, ConfigBundle, ProxyPoolTarget
from control.p3_geo_catalog import p3_country_geography
from control.prefill import fill_targets_direct
from control.tasks import provider_is_configured, queue_refill_proxy_pool


DEFAULT_COUNTRIES = (
    "DE",
    "ES",
    "CZ",
    "BE",
    "FR",
    "IT",
    "GB",
    "DK",
    "AU",
    "CA",
    "US",
)
COUNTRY_ALIASES = {"UK": "GB"}
def _tokens(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def _bounded(value: int, *, minimum: int = 1) -> int:
    return max(minimum, int(value))


class Command(BaseCommand):
    help = (
        "Pre-create and gradually fill P3 country, ISO subdivision, and curated "
        "city pools for the configuration bundles assigned to selected offices."
    )

    def add_arguments(self, parser):
        parser.add_argument("--office", action="append", required=True)
        parser.add_argument("--country", action="append", default=[])
        parser.add_argument("--country-target", type=int, default=1000)
        parser.add_argument("--country-threshold", type=int, default=200)
        parser.add_argument("--state-target", type=int, default=50)
        parser.add_argument("--state-threshold", type=int, default=10)
        parser.add_argument("--city-target", type=int, default=40)
        parser.add_argument("--city-threshold", type=int, default=8)
        parser.add_argument("--batch-size", type=int, default=100)
        parser.add_argument("--batch-timeout", type=int, default=900)
        parser.add_argument(
            "--direct-fill",
            action="store_true",
            help="Fill in batched DB writes instead of publishing one Celery task per target.",
        )
        parser.add_argument("--status-only", action="store_true")

    def handle(self, *args, **options):
        offices = list(dict.fromkeys(_tokens(options["office"])))
        countries = list(
            dict.fromkeys(
                COUNTRY_ALIASES.get(value.upper(), value.upper())
                for value in (_tokens(options["country"]) or DEFAULT_COUNTRIES)
            )
        )
        geography = {
            country: p3_country_geography(country) for country in countries
        }
        unsupported = [
            country
            for country, details in geography.items()
            if not details["regions"] and not details["cities"]
        ]
        if unsupported:
            raise CommandError(
                "No server P3 geography for: " + ", ".join(unsupported)
            )

        counts = {
            "country": _bounded(options["country_target"]),
            "state": _bounded(options["state_target"]),
            "city": _bounded(options["city_target"]),
        }
        thresholds = {
            "country": max(
                0,
                min(int(options["country_threshold"]), counts["country"] - 1),
            ),
            "state": max(
                0,
                min(int(options["state_threshold"]), counts["state"] - 1),
            ),
            "city": max(
                0,
                min(int(options["city_threshold"]), counts["city"] - 1),
            ),
        }

        assigned: dict[str, dict[int, str]] = defaultdict(dict)
        canonical = {office.casefold(): office for office in offices}
        rows = (
            ClientAccess.objects.filter(active=True, config_bundle__active=True)
            .order_by()
            .values("office_name", "config_bundle_id", "config_bundle__name")
            .distinct()
        )
        for row in rows.iterator(chunk_size=1000):
            key = str(row["office_name"] or "").strip().casefold()
            if key in canonical:
                assigned[key][row["config_bundle_id"]] = row["config_bundle__name"]
        missing_offices = [
            office for key, office in canonical.items() if not assigned.get(key)
        ]
        if missing_offices:
            raise CommandError(
                "No active assigned bundles for: " + ", ".join(missing_offices)
            )
        bundle_ids = {
            bundle_id
            for office_bundles in assigned.values()
            for bundle_id in office_bundles
        }
        bundles = list(
            ConfigBundle.objects.filter(pk__in=bundle_ids, active=True).order_by("name")
        )
        configured = [
            bundle
            for bundle in bundles
            if provider_is_configured("P3", bundle.get_payload())
        ]
        if len(configured) != len(bundles):
            missing = sorted(
                {bundle.name for bundle in bundles} - {bundle.name for bundle in configured}
            )
            raise CommandError("P3 credentials are missing for: " + ", ".join(missing))

        specs: dict[tuple[str, str, str], tuple[str, int, int]] = {}
        for country in countries:
            specs[(country, "", "")] = (
                "country",
                counts["country"],
                thresholds["country"],
            )
            for row in geography[country]["regions"]:
                specs[(country, str(row["code"]), "")] = (
                    "state",
                    counts["state"],
                    thresholds["state"],
                )
            # Massive gives city precedence over subdivision, so city pools are
            # intentionally stored with a blank region and shared by both the
            # country+city and country+state+city UI paths.
            for city in geography[country]["cities"]:
                specs[(country, "", str(city))] = (
                    "city",
                    counts["city"],
                    thresholds["city"],
                )

        expected = len(configured) * len(specs)
        self.stdout.write(
            f"Offices={len(offices)} bundles={len(configured)} countries={len(countries)} "
            f"locations_per_bundle={len(specs)} expected_targets={expected}"
        )

        current = list(
            ProxyPoolTarget.objects.filter(
                config_bundle_id__in=[bundle.pk for bundle in configured],
                provider_code="P3",
                country_code__in=countries,
            ).annotate(
                available_count=Count(
                    "entries", filter=Q(entries__state="available")
                )
            )
        )
        selected = [
            target
            for target in current
            if (target.country_code, target.region, target.city) in specs
        ]

        if options["status_only"]:
            self._status(
                configured,
                specs,
                [target for target in selected if target.active],
            )
            return

        existing = {
            (
                target.config_bundle_id,
                target.country_code,
                target.region,
                target.city,
            )
            for target in selected
        }
        missing_targets = []
        for bundle in configured:
            for (country, region, city), (_level, target_count, threshold) in specs.items():
                key = (bundle.pk, country, region, city)
                if key in existing:
                    continue
                missing_targets.append(
                    ProxyPoolTarget(
                        config_bundle=bundle,
                        provider_code="P3",
                        country_code=country,
                        region=region,
                        city=city,
                        target_count=target_count,
                        replenish_below=threshold,
                        active=True,
                    )
                )
        ProxyPoolTarget.objects.bulk_create(
            missing_targets,
            batch_size=1000,
            ignore_conflicts=True,
        )
        self.stdout.write(f"Targets created or recovered: {len(missing_targets)}")

        targets = list(
            ProxyPoolTarget.objects.filter(
                config_bundle_id__in=[bundle.pk for bundle in configured],
                provider_code="P3",
                country_code__in=countries,
            ).annotate(
                available_count=Count(
                    "entries", filter=Q(entries__state="available")
                )
            )
        )
        targets = [
            target
            for target in targets
            if (target.country_code, target.region, target.city) in specs
        ]
        changed = []
        for target in targets:
            _level, target_count, threshold = specs[
                (target.country_code, target.region, target.city)
            ]
            if (
                target.target_count != target_count
                or target.replenish_below != threshold
                or not target.active
            ):
                target.target_count = target_count
                target.replenish_below = threshold
                target.active = True
                changed.append(target)
        ProxyPoolTarget.objects.bulk_update(
            changed,
            ("target_count", "replenish_below", "active"),
            batch_size=1000,
        )

        needs_fill = [
            target
            for target in targets
            if int(target.available_count or 0)
            < max(1, target.replenish_below)
        ]
        batch_size = _bounded(options["batch_size"])
        timeout = _bounded(options["batch_timeout"], minimum=30)
        self.stdout.write(
            f"Targets needing ready inventory: {len(needs_fill)}; "
            f"batch size: {batch_size}"
        )
        if options["direct_fill"]:
            created = fill_targets_direct(
                needs_fill,
                target_batch_size=batch_size,
                progress=lambda done, total, rows: self.stdout.write(
                    f"DIRECT_FILL progress={done}/{total} entries_created={rows}"
                ),
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"PREFILL_DONE targets={len(targets)}/{expected} "
                    f"entries_created={created} failures=0"
                )
            )
            return
        failures: list[int] = []
        for offset in range(0, len(needs_fill), batch_size):
            batch = needs_fill[offset : offset + batch_size]
            batch_ids = [target.pk for target in batch]
            # A refill task itself fills the target to target_count.  Only wait
            # for the ready threshold here: an active office can reserve one
            # entry immediately after refill, and that must not stall the whole
            # prefill run while substantial ready inventory still remains.
            expected_counts = {
                target.pk: max(1, target.replenish_below)
                for target in batch
            }
            for target_id in batch_ids:
                queue_refill_proxy_pool(target_id)
            deadline = time.monotonic() + timeout
            missing = list(batch_ids)
            while missing and time.monotonic() < deadline:
                states = {
                    row["pk"]: (row["available_count"], row["refill_pending"])
                    for row in ProxyPoolTarget.objects.filter(pk__in=batch_ids)
                    .annotate(
                        available_count=Count(
                            "entries", filter=Q(entries__state="available")
                        )
                    )
                    .values("pk", "available_count", "refill_pending")
                }
                missing = [
                    target_id
                    for target_id in batch_ids
                    if states.get(target_id, (0, False))[0]
                    < expected_counts[target_id]
                ]
                for target_id in missing:
                    _available, pending = states.get(target_id, (0, False))
                    if not pending:
                        queue_refill_proxy_pool(target_id)
                if missing:
                    time.sleep(2)
            if missing:
                failures.extend(missing)
                self.stderr.write(
                    f"BATCH_TIMEOUT progress={min(offset + len(batch), len(needs_fill))}/"
                    f"{len(needs_fill)} missing={len(missing)}"
                )
            else:
                self.stdout.write(
                    f"BATCH_DONE progress={min(offset + len(batch), len(needs_fill))}/"
                    f"{len(needs_fill)}"
                )
        self.stdout.write(
            self.style.SUCCESS(
                f"PREFILL_DONE targets={len(targets)}/{expected} failures={len(failures)}"
            )
        )

    def _status(self, bundles, specs, targets) -> None:
        by_level: dict[str, list[ProxyPoolTarget]] = defaultdict(list)
        for target in targets:
            level, _count, _threshold = specs[
                (target.country_code, target.region, target.city)
            ]
            by_level[level].append(target)
        expected_by_level = {
            level: len(bundles)
            * sum(1 for spec in specs.values() if spec[0] == level)
            for level in ("country", "state", "city")
        }
        for level in ("country", "state", "city"):
            rows = by_level[level]
            ready = sum(
                1
                for target in rows
                if int(target.available_count or 0) >= target.replenish_below
                and not target.refill_pending
            )
            pending = sum(1 for target in rows if target.refill_pending)
            available = sum(int(target.available_count or 0) for target in rows)
            self.stdout.write(
                f"{level.upper()} targets={len(rows)}/{expected_by_level[level]} "
                f"ready={ready} pending={pending} available={available}"
            )
