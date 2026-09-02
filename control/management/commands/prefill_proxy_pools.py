from django.core.management.base import BaseCommand

from control.geo_catalog import sync_provider_geography
from control.models import ProxyPoolTarget
from control.tasks import ensure_pool_targets, refill_proxy_pool


class Command(BaseCommand):
    help = (
        "Synchronize global geography and synchronously prefill configured "
        "provider country/region proxy pools."
    )

    def add_arguments(self, parser):
        parser.add_argument("--target", type=int, default=1000)
        parser.add_argument("--threshold", type=int, default=200)
        parser.add_argument("--provider", default="")
        parser.add_argument("--country", default="")
        parser.add_argument("--skip-regions", action="store_true")
        parser.add_argument("--skip-geo-sync", action="store_true")

    def handle(self, *args, **options):
        target_count = max(1, options["target"])
        threshold = max(0, min(options["threshold"], target_count - 1))
        if not options["skip_geo_sync"]:
            try:
                summary = sync_provider_geography()
                self.stdout.write(
                    "Geography synchronized: "
                    + ", ".join(f"{key}={value}" for key, value in summary.items())
                )
            except Exception as exc:
                self.stderr.write(
                    "P2 live state sync failed; global countries and existing "
                    f"regions will still be used ({type(exc).__name__})."
                )
        created, configured = ensure_pool_targets(
            target_count=target_count,
            replenish_below=threshold,
            include_regions=not options["skip_regions"],
        )
        queryset = ProxyPoolTarget.objects.filter(active=True).order_by(
            "provider_code", "country_code", "region", "pk"
        )
        provider = options["provider"].strip().upper()
        country = options["country"].strip().upper()
        if provider:
            queryset = queryset.filter(provider_code=provider)
        if country:
            queryset = queryset.filter(country_code=country)
        filled = 0
        failed = 0
        for target in queryset:
            if target.target_count != target_count or target.replenish_below != threshold:
                target.target_count = target_count
                target.replenish_below = threshold
                target.save(update_fields=("target_count", "replenish_below", "updated_at"))
            try:
                created_entries = refill_proxy_pool.run(target.pk)
            except Exception as exc:
                failed += 1
                location = target.country_code
                if target.region:
                    location += f"/{target.region}"
                self.stderr.write(
                    f"FAILED {target.provider_code}/{location}: {type(exc).__name__}"
                )
                continue
            filled += 1
            available = target.entries.filter(state="available").count()
            location = target.country_code
            if target.region:
                location += f"/{target.region}"
            self.stdout.write(
                f"READY {target.provider_code}/{location}: "
                f"+{created_entries}, available={available}"
            )
        self.stdout.write(
            self.style.SUCCESS(
                f"Pool prefill complete: targets_created={created}, "
                f"configured={configured}, filled={filled}, failed={failed}."
            )
        )
