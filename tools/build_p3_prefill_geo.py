from __future__ import annotations

import argparse
import json
from pathlib import Path


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the compact P3 prefill geography used by the server."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--country", action="append", default=[])
    options = parser.parse_args()

    countries = tuple(
        dict.fromkeys(
            str(value).strip().upper()
            for value in (options.country or DEFAULT_COUNTRIES)
            if str(value).strip()
        )
    )
    payload = json.loads(options.source.read_text(encoding="utf-8"))
    result: dict[str, dict[str, list]] = {}
    for country in countries:
        regions = []
        for row in payload.get("subdivisions", {}).get(country, []):
            code = str(row.get("value") or row.get("code") or "").strip()
            name = str(row.get("name") or row.get("display") or code).strip()
            if code and name:
                regions.append({"code": code, "name": name})
        cities = []
        for row in payload.get("cities", {}).get(country, []):
            city = str(row.get("value") or row.get("name") or "").strip()
            if city and city not in cities:
                cities.append(city)
        result[country] = {"regions": regions, "cities": cities}

    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Wrote {options.output}: "
        f"{sum(len(row['regions']) for row in result.values())} regions, "
        f"{sum(len(row['cities']) for row in result.values())} cities."
    )


if __name__ == "__main__":
    main()
