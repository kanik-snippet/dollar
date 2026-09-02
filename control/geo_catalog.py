from __future__ import annotations

import json
import hashlib
import os
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

import pycountry

from .models import ConfigBundle, Provider, ProxyCountryFile, ProxyRegionCatalog


DYNAMIC_PROVIDER_CODES = ("P1", "P2", "P3", "P4")
REGION_PROVIDER_CODES = ("P1", "P2", "P3", "P4")
PROVIDER_DEFAULTS = {
    "P1": {"display_name": "P1", "display_order": 1},
    "P2": {"display_name": "P2", "display_order": 2},
    "P3": {"display_name": "P3", "display_order": 3},
    "P4": {"display_name": "P4", "display_order": 4},
}


def _config_value(config: dict[str, Any], *names: str) -> str:
    for name in names:
        value = str(config.get(name) or os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def p2_geo_account_key(email: str) -> str:
    """Return a stable pseudonymous identifier for one P2 geo account."""
    normalized = str(email or "").strip().casefold()
    if not normalized:
        return ""
    return hashlib.sha256(
        f"p2-geo-account-v1\0{normalized}".encode("utf-8")
    ).hexdigest()


def p2_geo_account_key_from_config(config: dict[str, Any]) -> str:
    email = ""
    for name in ("INFATICA_ACCOUNT_EMAIL", "P2_ACCOUNT_EMAIL"):
        email = str(config.get(name) or "").strip()
        if email:
            break
    return p2_geo_account_key(email)


def country_rows() -> list[tuple[str, str]]:
    rows = {
        str(item.alpha_2).upper(): str(item.name)
        for item in pycountry.countries
        if getattr(item, "alpha_2", None)
    }
    return sorted(rows.items(), key=lambda item: item[1].casefold())


def ensure_global_country_catalog() -> int:
    """Ensure every ISO country is visible for every dynamic provider."""
    providers: dict[str, Provider] = {}
    for code in DYNAMIC_PROVIDER_CODES:
        defaults = PROVIDER_DEFAULTS[code]
        provider, _created = Provider.objects.get_or_create(
            code=code,
            defaults={**defaults, "active": True},
        )
        update_fields: list[str] = []
        if not provider.active:
            provider.active = True
            update_fields.append("active")
        # P4 remains the stable app-facing label even though its backend
        # connection can be changed by configuration.
        if code == "P4" and provider.display_name != "P4":
            provider.display_name = "P4"
            update_fields.append("display_name")
        if update_fields:
            provider.save(update_fields=update_fields)
        providers[code] = provider

    countries = country_rows()
    country_codes = [code for code, _name in countries]
    ProxyCountryFile.objects.filter(
        provider__code__in=DYNAMIC_PROVIDER_CODES, country_code__in=country_codes
    ).update(active=True)
    existing = set(
        ProxyCountryFile.objects.filter(
            provider__code__in=DYNAMIC_PROVIDER_CODES,
        ).values_list("provider__code", "country_code")
    )
    missing = [
        ProxyCountryFile(
            provider=providers[provider_code],
            country_code=country_code,
            country_name=country_name,
            active=True,
        )
        for provider_code in DYNAMIC_PROVIDER_CODES
        for country_code, country_name in countries
        if (provider_code, country_code) not in existing
    ]
    ProxyCountryFile.objects.bulk_create(
        missing,
        batch_size=500,
        ignore_conflicts=True,
    )
    return len(missing)


def ensure_p1_region_catalog() -> int:
    """Seed the state/province codes Nimble officially accepts for US and CA."""
    provider = Provider.objects.get(code="P1")
    existing = set(
        ProxyRegionCatalog.objects.filter(provider=provider).values_list(
            "country_code", "region_code"
        )
    )
    missing: list[ProxyRegionCatalog] = []
    for item in pycountry.subdivisions:
        country_code = str(item.country_code).upper()
        if country_code not in {"US", "CA"}:
            continue
        region_code = str(item.code).rsplit("-", 1)[-1]
        if (country_code, region_code) in existing:
            continue
        missing.append(
            ProxyRegionCatalog(
                provider=provider,
                country_code=country_code,
                region_code=region_code,
                region_name=str(item.name),
                source="iso3166-2",
                active=True,
            )
        )
    ProxyRegionCatalog.objects.bulk_create(
        missing,
        batch_size=250,
        ignore_conflicts=True,
    )
    return len(missing)


def ensure_p3_region_catalog() -> int:
    """Expose ISO-3166-2 subdivisions supported by Massive/P3 targeting."""
    provider = Provider.objects.get(code="P3")
    current = {
        (row.country_code, row.region_code): row
        for row in ProxyRegionCatalog.objects.filter(provider=provider)
    }
    new_rows: list[ProxyRegionCatalog] = []
    changed_rows: list[ProxyRegionCatalog] = []
    for item in pycountry.subdivisions:
        country_code = str(item.country_code or "").upper()
        region_code = str(item.code or "").rsplit("-", 1)[-1]
        region_name = str(item.name or "").strip()
        if not country_code or not region_code or not region_name:
            continue
        row = current.get((country_code, region_code))
        if row is None:
            new_rows.append(
                ProxyRegionCatalog(
                    provider=provider,
                    country_code=country_code,
                    region_code=region_code,
                    region_name=region_name,
                    source="iso3166-2",
                    active=True,
                )
            )
        elif (
            row.region_name != region_name
            or row.source != "iso3166-2"
            or not row.active
        ):
            row.region_name = region_name
            row.source = "iso3166-2"
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


def _p4_region_code(name: str) -> str:
    """P4 accepts a normalized human-readable state in its proxy username."""
    value = "_".join(str(name or "").strip().lower().split())
    return "".join(char for char in value if char.isalnum() or char in {"_", "-"})


def ensure_p4_region_catalog() -> int:
    """Seed P4's state dropdown from ISO-3166-2; P4 deliberately has no cities."""
    provider = Provider.objects.get(code="P4")
    current = {
        (row.country_code, row.region_code): row
        for row in ProxyRegionCatalog.objects.filter(provider=provider)
    }
    new_rows: list[ProxyRegionCatalog] = []
    changed_rows: list[ProxyRegionCatalog] = []
    for item in pycountry.subdivisions:
        country_code = str(item.country_code).upper()
        region_name = str(item.name)
        region_code = _p4_region_code(region_name)
        if not country_code or not region_code:
            continue
        row = current.get((country_code, region_code))
        if row is None:
            new_rows.append(
                ProxyRegionCatalog(
                    provider=provider,
                    country_code=country_code,
                    region_code=region_code,
                    region_name=region_name,
                    source="iso3166-2-name",
                    active=True,
                )
            )
        elif (
            row.region_name != region_name
            or row.source != "iso3166-2-name"
            or not row.active
        ):
            row.region_name = region_name
            row.source = "iso3166-2-name"
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


def _flatten_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_dicts(item)


def _post_form_json(url: str, values: dict[str, str]) -> Any:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Tubelight-Provider-Geo/2.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _p2_account_credentials() -> tuple[str, str]:
    bundles = (
        ConfigBundle.objects.filter(active=True, clients__active=True)
        .distinct()
        .order_by("pk")
    )
    for bundle in bundles:
        config = bundle.get_payload()
        email = _config_value(
            config, "INFATICA_ACCOUNT_EMAIL", "P2_ACCOUNT_EMAIL"
        )
        password = _config_value(
            config, "INFATICA_ACCOUNT_PASSWORD", "P2_ACCOUNT_PASSWORD"
        )
        if email and password:
            return email, password
    email = _config_value({}, "INFATICA_ACCOUNT_EMAIL", "P2_ACCOUNT_EMAIL")
    password = _config_value(
        {}, "INFATICA_ACCOUNT_PASSWORD", "P2_ACCOUNT_PASSWORD"
    )
    return email, password


def sync_p2_live_regions() -> tuple[int, int]:
    """Sync Infatica's active numeric subdivision IDs without storing secrets."""
    email, password = _p2_account_credentials()
    if not email or not password:
        return 0, 0
    form = {"email": email, "password": password}
    nodes_payload = _post_form_json(
        "https://dashboard.infatica.io/includes/api/client/geo_nodes.php",
        form,
    )
    codes_payload = _post_form_json(
        "https://dashboard.infatica.io/includes/api/client/subdivision_codes.php",
        form,
    )

    code_by_name: dict[str, str] = {}
    for item in _flatten_dicts(codes_payload):
        name = str(item.get("subdivision") or "").strip()
        code = str(item.get("code") or "").strip()
        if name and code:
            code_by_name[name.casefold()] = code

    live: dict[tuple[str, str], str] = {}
    active_countries: set[str] = set()
    for item in _flatten_dicts(nodes_payload):
        country = str(item.get("country") or "").strip().upper()
        subdivision = str(item.get("subdivision") or "").strip()
        region_code = code_by_name.get(subdivision.casefold(), "")
        if country:
            active_countries.add(country)
        if country and subdivision and region_code:
            live[(country, region_code)] = subdivision

    provider = Provider.objects.get(code="P2")
    current = {
        (row.country_code, row.region_code): row
        for row in ProxyRegionCatalog.objects.filter(provider=provider)
    }
    new_rows: list[ProxyRegionCatalog] = []
    changed_rows: list[ProxyRegionCatalog] = []
    for key, name in live.items():
        row = current.get(key)
        if row is None:
            new_rows.append(
                ProxyRegionCatalog(
                    provider=provider,
                    country_code=key[0],
                    region_code=key[1],
                    region_name=name,
                    source="infatica-live",
                    active=True,
                )
            )
        elif (
            row.region_name != name
            or row.source != "infatica-live"
            or not row.active
        ):
            row.region_name = name
            row.source = "infatica-live"
            row.active = True
            changed_rows.append(row)
    ProxyRegionCatalog.objects.bulk_create(
        new_rows,
        batch_size=250,
        ignore_conflicts=True,
    )
    if changed_rows:
        ProxyRegionCatalog.objects.bulk_update(
            changed_rows,
            ("region_name", "source", "active"),
            batch_size=250,
        )
    return len(active_countries), len(new_rows) + len(changed_rows)


def sync_provider_geography() -> dict[str, int]:
    countries_created = ensure_global_country_catalog()
    p1_regions_created = ensure_p1_region_catalog()
    p3_regions_created = ensure_p3_region_catalog()
    p4_regions_created = ensure_p4_region_catalog()
    p2_countries_seen, p2_regions_synced = sync_p2_live_regions()
    return {
        "countries_created": countries_created,
        "p1_regions_created": p1_regions_created,
        "p3_regions_created": p3_regions_created,
        "p4_regions_created": p4_regions_created,
        "p2_countries_seen": p2_countries_seen,
        "p2_regions_synced": p2_regions_synced,
    }
