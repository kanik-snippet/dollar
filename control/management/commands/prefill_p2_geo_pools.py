from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Count, Q

from control.geo_catalog import (
    _flatten_dicts,
    _post_form_json,
    ensure_global_country_catalog,
    p2_geo_account_key,
)
from control.models import (
    ClientAccess,
    ConfigBundle,
    Provider,
    ProxyCityCatalog,
    ProxyPoolTarget,
    ProxyRegionCatalog,
)
from control.prefill import fill_targets_direct
from control.tasks import provider_is_configured, queue_refill_proxy_pool


DEFAULT_COUNTRIES = (
    "US", "CA", "AU", "DE", "ES", "CZ", "BE", "FR", "IT", "GB", "DK",
)
COUNTRY_ALIASES = {"UK": "GB"}
GEO_NODES_URL = (
    "https://dashboard.infatica.io/includes/api/client/geo_nodes.php"
)
SUBDIVISION_CODES_URL = (
    "https://dashboard.infatica.io/includes/api/client/subdivision_codes.php"
)


def _tokens(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def _bounded(value: int, *, minimum: int = 1) -> int:
    return max(minimum, int(value))


def _geo_credentials(config: dict[str, Any]) -> tuple[str, str]:
    def payload_value(*names: str) -> str:
        for name in names:
            value = str(config.get(name) or "").strip()
            if value:
                return value
        return ""

    return (
        payload_value("INFATICA_ACCOUNT_EMAIL", "P2_ACCOUNT_EMAIL"),
        payload_value("INFATICA_ACCOUNT_PASSWORD", "P2_ACCOUNT_PASSWORD"),
    )


def _live_specs(
    *,
    email: str,
    password: str,
    countries: list[str],
    counts: dict[str, int],
    thresholds: dict[str, int],
) -> tuple[
    dict[tuple[str, str, str], tuple[str, int, int]],
    dict[str, dict[str, str]],
    dict[str, int],
]:
    form = {"email": email, "password": password}
    nodes_payload = _post_form_json(GEO_NODES_URL, form)
    codes_payload = _post_form_json(SUBDIVISION_CODES_URL, form)

    code_by_name: dict[str, str] = {}
    for item in _flatten_dicts(codes_payload):
        name = str(item.get("subdivision") or "").strip()
        code = str(item.get("code") or "").strip()
        if name and code.isdigit():
            code_by_name[name.casefold()] = code
    if not code_by_name:
        raise ValueError("Infatica returned no numeric subdivision codes")

    selected = set(countries)
    regions: dict[str, dict[str, str]] = defaultdict(dict)
    cities: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    location_rows_seen = 0
    selected_countries_seen: set[str] = set()
    nodes_seen = 0
    skipped_without_numeric_region = 0
    skipped_long_city = 0
    for item in _flatten_dicts(nodes_payload):
        country = str(item.get("country") or "").strip().upper()
        if country:
            location_rows_seen += 1
        if country not in selected:
            continue
        nodes_seen += 1
        selected_countries_seen.add(country)
        subdivision = str(item.get("subdivision") or "").strip()
        region_code = code_by_name.get(subdivision.casefold(), "")
        if not subdivision or not region_code:
            skipped_without_numeric_region += 1
            continue
        regions[country][region_code] = subdivision
        city = str(item.get("city") or "").strip()
        if not city:
            continue
        if len(city) > ProxyPoolTarget._meta.get_field("city").max_length:
            skipped_long_city += 1
            continue
        cities[(country, region_code)].setdefault(city.casefold(), city)
    if not location_rows_seen:
        raise ValueError("Infatica returned no live location rows")
    missing_countries = sorted(selected - selected_countries_seen)
    if missing_countries:
        raise ValueError(
            "Infatica returned no live rows for requested countries: "
            + ", ".join(missing_countries)
        )
    missing_region_countries = sorted(
        country for country in selected if not regions.get(country)
    )
    if missing_region_countries:
        raise ValueError(
            "Infatica returned no numeric states for requested countries: "
            + ", ".join(missing_region_countries)
        )
    missing_city_countries = sorted(
        country
        for country in selected
        if not any(key[0] == country and values for key, values in cities.items())
    )
    if missing_city_countries:
        raise ValueError(
            "Infatica returned no cities for requested countries: "
            + ", ".join(missing_city_countries)
        )

    specs: dict[tuple[str, str, str], tuple[str, int, int]] = {}
    for country in countries:
        specs[(country, "", "")] = (
            "country",
            counts["country"],
            thresholds["country"],
        )
        for region_code in sorted(
            regions.get(country, {}),
            key=lambda code: regions[country][code].casefold(),
        ):
            specs[(country, region_code, "")] = (
                "state",
                counts["state"],
                thresholds["state"],
            )
            for city in sorted(
                cities.get((country, region_code), {}).values(),
                key=str.casefold,
            ):
                specs[(country, region_code, city)] = (
                    "city",
                    counts["city"],
                    thresholds["city"],
                )

    summary = {
        "nodes_seen": nodes_seen,
        "states": sum(len(rows) for rows in regions.values()),
        "cities": sum(len(rows) for rows in cities.values()),
        "skipped_without_numeric_region": skipped_without_numeric_region,
        "skipped_long_city": skipped_long_city,
    }
    return specs, regions, summary


def _sync_region_catalog(
    regions: dict[str, dict[str, str]],
    countries: list[str],
) -> int:
    ensure_global_country_catalog()
    provider = Provider.objects.get(code="P2")
    current = {
        (row.country_code, row.region_code): row
        for row in ProxyRegionCatalog.objects.filter(
            provider=provider,
            country_code__in=countries,
        )
    }
    new_rows: list[ProxyRegionCatalog] = []
    changed_rows: list[ProxyRegionCatalog] = []
    for country, country_regions in regions.items():
        for region_code, region_name in country_regions.items():
            row = current.get((country, region_code))
            if row is None:
                new_rows.append(
                    ProxyRegionCatalog(
                        provider=provider,
                        country_code=country,
                        region_code=region_code,
                        region_name=region_name,
                        source="infatica-live",
                        active=True,
                    )
                )
            elif (
                row.region_name != region_name
                or row.source != "infatica-live"
                or not row.active
            ):
                row.region_name = region_name
                row.source = "infatica-live"
                row.active = True
                changed_rows.append(row)
    ProxyRegionCatalog.objects.bulk_create(
        new_rows,
        batch_size=500,
        ignore_conflicts=True,
    )
    if changed_rows:
        ProxyRegionCatalog.objects.bulk_update(
            changed_rows,
            ("region_name", "source", "active"),
            batch_size=500,
        )
    return len(new_rows) + len(changed_rows)


def _sync_city_catalog(
    account_key: str,
    specs: dict[tuple[str, str, str], tuple[str, int, int]],
    countries: list[str],
) -> tuple[int, int]:
    """Store P2 geography once globally, not once per configuration bundle."""
    if len(account_key) != 64:
        raise ValueError("P2 geo account key is unavailable")
    provider = Provider.objects.get(code="P2")
    expected = {
        (country, region, city)
        for country, region, city in specs
        if city
    }
    current = {
        (row.country_code, row.region_code, row.city_name): row
        for row in ProxyCityCatalog.objects.filter(
            provider=provider,
            account_key=account_key,
            country_code__in=countries,
        )
    }
    new_rows: list[ProxyCityCatalog] = []
    changed_rows: list[ProxyCityCatalog] = []
    for country, region, city in expected:
        row = current.get((country, region, city))
        if row is None:
            new_rows.append(
                ProxyCityCatalog(
                    provider=provider,
                    account_key=account_key,
                    country_code=country,
                    region_code=region,
                    city_name=city,
                    source="infatica-live",
                    active=True,
                )
            )
        elif row.source != "infatica-live" or not row.active:
            row.source = "infatica-live"
            row.active = True
            changed_rows.append(row)
    stale_ids = [
        row.pk
        for key, row in current.items()
        if row.active and key not in expected
    ]
    ProxyCityCatalog.objects.bulk_create(
        new_rows,
        batch_size=1000,
        ignore_conflicts=True,
    )
    if changed_rows:
        ProxyCityCatalog.objects.bulk_update(
            changed_rows,
            ("source", "active"),
            batch_size=1000,
        )
    if stale_ids:
        ProxyCityCatalog.objects.filter(pk__in=stale_ids).update(active=False)
    return len(new_rows) + len(changed_rows), len(stale_ids)


class Command(BaseCommand):
    help = (
        "Fetch live P2 geography once, synchronize the shared city catalog, "
        "and fill country/state pools for bundles assigned to selected offices."
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
        parser.add_argument(
            "--catalog-only",
            action="store_true",
            help=(
                "Synchronize live P2 states/cities without multiplying city "
                "proxy pools across every bundle."
            ),
        )
        parser.add_argument(
            "--prefill-city-pools",
            action="store_true",
            help=(
                "Explicit legacy mode: multiply every city pool across every "
                "selected bundle. Normally cities are generated instantly "
                "only when selected."
            ),
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
        invalid_countries = [
            country
            for country in countries
            if len(country) != 2 or not country.isalpha()
        ]
        if invalid_countries:
            raise CommandError(
                "Invalid two-letter country code(s): "
                + ", ".join(invalid_countries)
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
            ConfigBundle.objects.filter(pk__in=bundle_ids, active=True).order_by(
                "name"
            )
        )
        bundle_configs = {bundle.pk: bundle.get_payload() for bundle in bundles}
        missing_api = [
            bundle.name
            for bundle in bundles
            if not provider_is_configured("P2", bundle_configs[bundle.pk])
        ]
        if missing_api:
            raise CommandError(
                "P2 API Tool credentials are missing for: "
                + ", ".join(sorted(missing_api))
            )

        account_groups: dict[str, dict[str, Any]] = {}
        bundle_account: dict[int, str] = {}
        missing_geo: list[str] = []
        for bundle in bundles:
            email, password = _geo_credentials(bundle_configs[bundle.pk])
            account_key = p2_geo_account_key(email)
            if not account_key or not password:
                missing_geo.append(bundle.name)
                continue
            group = account_groups.setdefault(
                account_key,
                {
                    "email": email,
                    "password": password,
                    "bundles": [],
                },
            )
            if (
                group["email"].strip().casefold() != email.strip().casefold()
                or group["password"] != password
            ):
                raise CommandError(
                    "Bundles for P2 geo account "
                    f"{account_key[:12]} use conflicting credentials."
                )
            group["bundles"].append(bundle)
            bundle_account[bundle.pk] = account_key
        if missing_geo:
            raise CommandError(
                "P2 account geo credentials are missing for: "
                + ", ".join(sorted(missing_geo))
            )

        catalog_specs_by_account: dict[
            str, dict[tuple[str, str, str], tuple[str, int, int]]
        ] = {}
        pool_specs_by_account: dict[
            str, dict[tuple[str, str, str], tuple[str, int, int]]
        ] = {}
        regions_by_account: dict[str, dict[str, dict[str, str]]] = {}
        summaries_by_account: dict[str, dict[str, int]] = {}
        for account_key, group in account_groups.items():
            try:
                catalog_specs, regions, geo_summary = _live_specs(
                    email=group["email"],
                    password=group["password"],
                    countries=countries,
                    counts=counts,
                    thresholds=thresholds,
                )
            except Exception as exc:
                raise CommandError(
                    "P2 live geography could not be loaded for account "
                    f"{account_key[:12]} ({type(exc).__name__})."
                ) from exc
            pool_specs = catalog_specs
            if not options["catalog_only"] and not options["prefill_city_pools"]:
                pool_specs = {
                    key: value
                    for key, value in catalog_specs.items()
                    if not key[2]
                }
            catalog_specs_by_account[account_key] = catalog_specs
            pool_specs_by_account[account_key] = pool_specs
            regions_by_account[account_key] = regions
            summaries_by_account[account_key] = geo_summary

        expected = sum(
            len(group["bundles"]) * len(pool_specs_by_account[account_key])
            for account_key, group in account_groups.items()
        )
        self.stdout.write(
            f"Offices={len(offices)} bundles={len(bundles)} "
            f"accounts={len(account_groups)} countries={len(countries)} "
            f"expected_targets={expected}"
        )
        for account_key, geo_summary in summaries_by_account.items():
            self.stdout.write(
                f"Account={account_key[:12]} "
                f"bundles={len(account_groups[account_key]['bundles'])} "
                f"locations={len(pool_specs_by_account[account_key])} "
                f"nodes={geo_summary['nodes_seen']} "
                f"states={geo_summary['states']} cities={geo_summary['cities']}"
            )
            if geo_summary["skipped_without_numeric_region"]:
                self.stderr.write(
                    f"Account {account_key[:12]} skipped live nodes without "
                    "a numeric subdivision ID: "
                    f"{geo_summary['skipped_without_numeric_region']}"
                )
            if geo_summary["skipped_long_city"]:
                self.stderr.write(
                    f"Account {account_key[:12]} skipped city names longer "
                    "than the target field: "
                    f"{geo_summary['skipped_long_city']}"
                )

        if options["catalog_only"]:
            synced_regions = 0
            synced_cities = 0
            stale_cities = 0
            for account_key in account_groups:
                synced_regions += _sync_region_catalog(
                    regions_by_account[account_key], countries
                )
                changed, stale = _sync_city_catalog(
                    account_key,
                    catalog_specs_by_account[account_key],
                    countries,
                )
                synced_cities += changed
                stale_cities += stale
            self.stdout.write(
                self.style.SUCCESS(
                    "CATALOG_DONE "
                    f"regions_synced={synced_regions} "
                    f"cities_synced={synced_cities} "
                    f"cities_deactivated={stale_cities}"
                )
            )
            return

        current = list(
            ProxyPoolTarget.objects.filter(
                config_bundle_id__in=[bundle.pk for bundle in bundles],
                provider_code="P2",
                country_code__in=countries,
            ).annotate(
                available_count=Count(
                    "entries", filter=Q(entries__state="available")
                )
            )
        )
        def specs_for_bundle(bundle_id: int):
            account_key = bundle_account.get(bundle_id, "")
            return pool_specs_by_account.get(account_key, {})

        selected = [
            target
            for target in current
            if (
                target.country_code,
                target.region,
                target.city,
            ) in specs_for_bundle(target.config_bundle_id)
        ]

        if options["status_only"]:
            for account_key, group in account_groups.items():
                group_bundle_ids = {
                    bundle.pk for bundle in group["bundles"]
                }
                self.stdout.write(f"ACCOUNT {account_key[:12]}")
                self._status(
                    group["bundles"],
                    pool_specs_by_account[account_key],
                    [
                        target
                        for target in selected
                        if target.active
                        and target.config_bundle_id in group_bundle_ids
                    ],
                )
            return

        synced_regions = 0
        synced_cities = 0
        stale_cities = 0
        for account_key in account_groups:
            synced_regions += _sync_region_catalog(
                regions_by_account[account_key], countries
            )
            changed_count, stale_count = _sync_city_catalog(
                account_key,
                catalog_specs_by_account[account_key],
                countries,
            )
            synced_cities += changed_count
            stale_cities += stale_count
        self.stdout.write(f"P2 region catalog rows synchronized: {synced_regions}")
        self.stdout.write(
            "P2 city catalog rows synchronized: "
            f"{synced_cities}; deactivated: {stale_cities}"
        )

        stale_target_ids = [
            target.pk
            for target in current
            if target.active
            and (options["prefill_city_pools"] or not target.city)
            and (
                target.country_code,
                target.region,
                target.city,
            ) not in specs_for_bundle(target.config_bundle_id)
        ]
        if stale_target_ids:
            ProxyPoolTarget.objects.filter(pk__in=stale_target_ids).update(
                active=False,
                refill_pending=False,
                refill_requested_at=None,
            )
        self.stdout.write(f"Stale P2 targets deactivated: {len(stale_target_ids)}")

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
        for bundle in bundles:
            bundle_specs = specs_for_bundle(bundle.pk)
            for (country, region, city), (
                _level,
                target_count,
                threshold,
            ) in bundle_specs.items():
                key = (bundle.pk, country, region, city)
                if key in existing:
                    continue
                missing_targets.append(
                    ProxyPoolTarget(
                        config_bundle=bundle,
                        provider_code="P2",
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
        self.stdout.write(f"Targets created: {len(missing_targets)}")

        targets = list(
            ProxyPoolTarget.objects.filter(
                config_bundle_id__in=[bundle.pk for bundle in bundles],
                provider_code="P2",
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
            if (
                target.country_code,
                target.region,
                target.city,
            ) in specs_for_bundle(target.config_bundle_id)
        ]
        changed = []
        for target in targets:
            _level, target_count, threshold = specs_for_bundle(
                target.config_bundle_id
            )[
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
        if changed:
            ProxyPoolTarget.objects.bulk_update(
                changed,
                ("target_count", "replenish_below", "active"),
                batch_size=1000,
            )

        needs_fill = [
            target
            for target in targets
            if int(target.available_count or 0) < max(1, target.replenish_below)
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
            expected_counts = {
                target.pk: max(1, target.replenish_below) for target in batch
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
                    "BATCH_TIMEOUT "
                    f"progress={min(offset + len(batch), len(needs_fill))}/"
                    f"{len(needs_fill)} missing={len(missing)}"
                )
            else:
                self.stdout.write(
                    "BATCH_DONE "
                    f"progress={min(offset + len(batch), len(needs_fill))}/"
                    f"{len(needs_fill)}"
                )
        self.stdout.write(
            self.style.SUCCESS(
                f"PREFILL_DONE targets={len(targets)}/{expected} "
                f"failures={len(failures)}"
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
                f"{level.upper()} targets={len(rows)}/"
                f"{expected_by_level[level]} ready={ready} pending={pending} "
                f"available={available}"
            )
