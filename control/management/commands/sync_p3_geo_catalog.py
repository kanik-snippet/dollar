from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from control.p3_geo_catalog import sync_p3_country_geography


COUNTRY_ALIASES = {"UK": "GB"}


def _tokens(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


class Command(BaseCommand):
    help = "Import the full dynamic P3 subdivision/city catalog into the database."

    def add_arguments(self, parser):
        parser.add_argument("--source", required=True)
        parser.add_argument("--country", action="append", default=[])

    def handle(self, *args, **options):
        source = Path(options["source"]).expanduser().resolve()
        if not source.is_file():
            raise CommandError(f"P3 geography source is missing: {source}")
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CommandError(f"Invalid P3 geography source: {exc}") from exc
        subdivisions = payload.get("subdivisions")
        cities = payload.get("cities")
        if not isinstance(subdivisions, dict) or not isinstance(cities, dict):
            raise CommandError("P3 geography source must contain subdivisions and cities")
        requested = _tokens(options["country"])
        countries = list(
            dict.fromkeys(
                COUNTRY_ALIASES.get(value.upper(), value.upper())
                for value in (requested or sorted(cities))
            )
        )
        missing = [country for country in countries if country not in cities]
        if missing:
            raise CommandError("No P3 city geography for: " + ", ".join(missing))

        totals = [0, 0, 0, 0]
        for index, country in enumerate(countries, 1):
            region_rows = subdivisions.get(country) or []
            city_rows = cities.get(country) or []
            if not isinstance(region_rows, list) or not isinstance(city_rows, list):
                raise CommandError(f"Invalid geography rows for: {country}")
            with transaction.atomic():
                result = sync_p3_country_geography(country, region_rows, city_rows)
            totals = [left + right for left, right in zip(totals, result)]
            self.stdout.write(
                f"SYNC country={country} progress={index}/{len(countries)} "
                f"regions={len(region_rows)} cities={len(city_rows)}"
            )
        self.stdout.write(
            self.style.SUCCESS(
                "P3_GEO_SYNC_DONE "
                f"countries={len(countries)} regions_changed={totals[0]} "
                f"regions_disabled={totals[1]} cities_changed={totals[2]} "
                f"cities_disabled={totals[3]}"
            )
        )
