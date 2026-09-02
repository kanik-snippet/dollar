from __future__ import annotations

import re
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from control.models import Provider, ProxyCountryFile


SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class Command(BaseCommand):
    help = "Import provider/country TXT files into encrypted PostgreSQL rows."

    def add_arguments(self, parser):
        parser.add_argument("root", help="Folder containing P1/US__United States.txt style files")
        parser.add_argument(
            "--disable-missing",
            action="store_true",
            help="Disable existing catalog rows not present in this import.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        root = Path(options["root"]).resolve()
        if not root.is_dir():
            raise CommandError(f"Catalog folder not found: {root}")

        imported: set[tuple[str, str]] = set()
        file_count = 0
        for provider_dir in sorted(path for path in root.iterdir() if path.is_dir()):
            provider_code = provider_dir.name.strip()
            if not SAFE_ID.fullmatch(provider_code):
                raise CommandError(f"Unsafe provider folder name: {provider_dir.name}")
            provider, _ = Provider.objects.get_or_create(
                code=provider_code,
                defaults={"display_name": provider_code, "display_order": 0, "active": True},
            )
            for txt_path in sorted(provider_dir.glob("*.txt")):
                raw_stem = txt_path.stem.strip()
                if "__" in raw_stem:
                    country_code, country_name = raw_stem.split("__", 1)
                else:
                    country_code = re.sub(r"[^A-Za-z0-9_-]+", "-", raw_stem).strip("-")
                    country_name = raw_stem.replace("_", " ").replace("-", " ").strip().title()
                if not SAFE_ID.fullmatch(country_code):
                    raise CommandError(f"Unsafe country id in file: {txt_path.name}")
                content = txt_path.read_text(encoding="utf-8-sig")
                row, created = ProxyCountryFile.objects.get_or_create(
                    provider=provider,
                    country_code=country_code,
                    defaults={"country_name": country_name, "active": True},
                )
                row.country_name = country_name
                row.active = True
                if not created:
                    row.version += 1
                row.set_content(content)
                row.save()
                imported.add((provider.code, row.country_code))
                file_count += 1

        if options["disable_missing"]:
            for row in ProxyCountryFile.objects.select_related("provider"):
                if (row.provider.code, row.country_code) not in imported and row.active:
                    row.active = False
                    row.save(update_fields=("active", "updated_at"))

        self.stdout.write(self.style.SUCCESS(f"Imported {file_count} encrypted proxy TXT file(s)."))
