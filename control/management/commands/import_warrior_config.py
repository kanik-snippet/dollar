from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from control.models import ConfigBundle


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and value:
            values[key] = value
    return values


class Command(BaseCommand):
    help = "Import a tubelight_config-style key=value file into an encrypted bundle."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Plaintext tubelight_config-style file")
        parser.add_argument("--name", required=True, help="Config bundle name")
        parser.add_argument("--bundle-version", type=int, default=1)

    @transaction.atomic
    def handle(self, *args, **options):
        path = Path(options["path"]).resolve()
        if not path.is_file():
            raise CommandError(f"Configuration file not found: {path}")
        try:
            values = parse_key_values(path.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise CommandError(f"Could not read configuration file: {exc}") from exc
        if not values:
            raise CommandError("The configuration file contains no non-empty values.")
        version = max(1, int(options["bundle_version"]))
        bundle, _ = ConfigBundle.objects.get_or_create(name=options["name"])
        bundle.version = version
        bundle.active = True
        bundle.set_payload(values)
        bundle.save()
        self.stdout.write(
            self.style.SUCCESS(
                f"Stored {len(values)} encrypted configuration field(s) in "
                f"bundle '{bundle.name}' v{bundle.version}."
            )
        )
        self.stdout.write(
            self.style.WARNING(
                "Delete the plaintext source file securely after verifying the bundle."
            )
        )
