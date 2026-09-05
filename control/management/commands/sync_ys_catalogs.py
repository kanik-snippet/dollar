import json

from django.core.management.base import BaseCommand, CommandError

from control.browser_catalog import sync_catalogs
from control.models import BrowserCatalogSnapshot


class Command(BaseCommand):
    help = "Import allowlisted YS metadata only; never downloads browsers or uploads profile data."

    def add_arguments(self, parser):
        parser.add_argument("--status", action="store_true", help="Show last sync status without contacting YS.")

    def handle(self, *args, **options):
        if options["status"]:
            fields = ("name", "revision", "last_attempt_at", "last_success_at", "data_updated_at", "last_error", "lease_until")
            self.stdout.write(json.dumps(list(BrowserCatalogSnapshot.objects.values(*fields)), default=str, indent=2))
            return
        results = sync_catalogs(force=True)
        self.stdout.write(json.dumps(results, indent=2))
        if any(result["status"] in {"failed", "lease_lost"} for result in results):
            raise CommandError("One or more catalogs did not sync. Valid previous snapshots were retained.")
