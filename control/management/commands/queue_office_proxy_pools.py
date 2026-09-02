from __future__ import annotations

from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError

from control.models import ClientAccess, ConfigBundle, ProxyPoolTarget
from control.tasks import provider_is_configured, queue_refill_proxy_pool


DEFAULT_COUNTRIES = (
    "US", "GB", "CA", "AU", "CN", "DE", "BE", "FR", "NZ", "MX",
    "JP", "CH", "AE", "ZA", "SA", "TR", "NL", "SK", "BR", "RU",
    "HU", "IN", "IT", "HK", "SG", "PT", "TH", "NO", "CL",
)


def _tokens(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


class Command(BaseCommand):
    help = (
        "Create and queue proxy pools for every unique active configuration "
        "bundle assigned to one or more offices."
    )

    def add_arguments(self, parser):
        parser.add_argument("--office", action="append", required=True)
        parser.add_argument("--provider", default="P1")
        parser.add_argument("--country", action="append", default=[])
        parser.add_argument("--target", type=int, default=1000)
        parser.add_argument("--threshold", type=int, default=200)

    def handle(self, *args, **options):
        requested_offices = _tokens(options["office"])
        countries = [
            value.upper() for value in (_tokens(options["country"]) or DEFAULT_COUNTRIES)
        ]
        provider = str(options["provider"] or "P1").strip().upper()
        target_count = max(1, int(options["target"]))
        threshold = max(0, min(int(options["threshold"]), target_count - 1))
        if provider not in {"P1", "P2", "P3"}:
            raise CommandError("Provider must be P1, P2 or P3.")

        assigned: dict[str, dict[int, str]] = defaultdict(dict)
        canonical = {name.casefold(): name for name in requested_offices}
        rows = (
            ClientAccess.objects.filter(
                active=True,
                config_bundle__isnull=False,
                config_bundle__active=True,
            )
            .order_by()
            .values("office_name", "config_bundle_id", "config_bundle__name")
            .distinct()
        )
        for row in rows.iterator(chunk_size=1000):
            office = str(row["office_name"] or "").strip()
            key = office.casefold()
            if key in canonical:
                assigned[key][row["config_bundle_id"]] = row["config_bundle__name"]

        missing_offices = [
            name for key, name in canonical.items() if not assigned.get(key)
        ]
        bundle_ids = {
            bundle_id
            for office_bundles in assigned.values()
            for bundle_id in office_bundles
        }
        bundles = list(
            ConfigBundle.objects.filter(pk__in=bundle_ids, active=True).order_by("name")
        )

        self.stdout.write("Assigned bundles detected:")
        for key, display_name in canonical.items():
            names = sorted(assigned.get(key, {}).values(), key=str.casefold)
            self.stdout.write(f"  {display_name}: {len(names)}")
            for name in names:
                self.stdout.write(f"    - {name}")

        configured: list[ConfigBundle] = []
        missing_credentials: list[str] = []
        for bundle in bundles:
            if provider_is_configured(provider, bundle.get_payload()):
                configured.append(bundle)
            else:
                missing_credentials.append(bundle.name)

        created = queued = pending = ready = 0
        for bundle in configured:
            for country in countries:
                target, was_created = ProxyPoolTarget.objects.get_or_create(
                    config_bundle=bundle,
                    provider_code=provider,
                    country_code=country,
                    region="",
                    city="",
                    defaults={
                        "target_count": target_count,
                        "replenish_below": threshold,
                        "active": True,
                    },
                )
                if was_created:
                    created += 1
                updates = []
                for field, value in (
                    ("target_count", target_count),
                    ("replenish_below", threshold),
                    ("active", True),
                ):
                    if getattr(target, field) != value:
                        setattr(target, field, value)
                        updates.append(field)
                if updates:
                    target.save(update_fields=(*updates, "updated_at"))
                available = target.entries.filter(state="available").count()
                if available >= target_count:
                    ready += 1
                elif queue_refill_proxy_pool(target.pk):
                    queued += 1
                else:
                    pending += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("RESULT"))
        self.stdout.write(f"Offices requested: {len(requested_offices)}")
        self.stdout.write(f"Unique assigned bundles: {len(bundles)}")
        self.stdout.write(f"{provider}-configured bundles: {len(configured)}")
        self.stdout.write(f"Countries per bundle: {len(countries)}")
        self.stdout.write(f"Targets expected: {len(configured) * len(countries)}")
        self.stdout.write(f"Targets created: {created}")
        self.stdout.write(f"Refills queued: {queued}")
        self.stdout.write(f"Already ready: {ready}")
        self.stdout.write(f"Already pending: {pending}")
        if missing_credentials:
            self.stderr.write("Bundles missing provider credentials:")
            for name in missing_credentials:
                self.stderr.write(f"  - {name}")
        if missing_offices:
            self.stderr.write("Offices with no active assigned bundle:")
            for name in missing_offices:
                self.stderr.write(f"  - {name}")
