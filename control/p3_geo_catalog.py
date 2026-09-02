from __future__ import annotations

from typing import Any

from .models import Provider, ProxyCityCatalog, ProxyRegionCatalog


P3_GEO_ACCOUNT_KEY = "p3-global-v1"
P3_GEO_SOURCE = "dynamic-geo-v1"

# ISO-3166-2 exposes both Spanish autonomous communities and provinces.
# Massive's subdivision selector accepts the top-level autonomous-community
# codes; province-only codes such as M (Madrid province) produce unusable
# proxy sessions. Keep only the provider-supported state-level choices.
P3_REGION_ALLOWLISTS = {
    "ES": frozenset(
        {
            "AN", "AR", "AS", "CB", "CE", "CL", "CM", "CN", "CT",
            "EX", "GA", "IB", "MC", "MD", "ML", "NC", "PV", "RI", "VC",
        }
    ),
}


def p3_country_geography(country_code: str) -> dict[str, Any]:
    """Return the server-managed P3 subdivisions and country-wide city list."""
    country = str(country_code or "").strip().upper()
    if not country:
        return {"regions": [], "cities": []}
    regions = list(
        ProxyRegionCatalog.objects.filter(
            provider__code="P3",
            provider__active=True,
            country_code=country,
            active=True,
        )
        .order_by("region_name", "region_code")
        .values("region_code", "region_name")
    )
    cities = list(
        ProxyCityCatalog.objects.filter(
            provider__code="P3",
            provider__active=True,
            account_key=P3_GEO_ACCOUNT_KEY,
            country_code=country,
            region_code="",
            active=True,
        )
        .order_by("city_name")
        .values_list("city_name", flat=True)
        .distinct()
    )
    return {
        "regions": [
            {"code": row["region_code"], "name": row["region_name"]}
            for row in regions
        ],
        "cities": cities,
    }


def p3_city_name(country_code: str, city_name: str) -> str:
    """Return the canonical live P3 city name, or an empty string."""
    country = str(country_code or "").strip().upper()
    city = str(city_name or "").strip()
    if not country or not city:
        return ""
    return str(
        ProxyCityCatalog.objects.filter(
            provider__code="P3",
            provider__active=True,
            account_key=P3_GEO_ACCOUNT_KEY,
            country_code=country,
            region_code="",
            city_name__iexact=city,
            active=True,
        )
        .order_by("city_name")
        .values_list("city_name", flat=True)
        .first()
        or ""
    )


def sync_p3_country_geography(
    country_code: str,
    region_rows: list[dict[str, Any]],
    city_rows: list[dict[str, Any]],
) -> tuple[int, int, int, int]:
    """Upsert one country and disable stale P3 geography for that country."""
    country = str(country_code or "").strip().upper()
    if not country:
        raise ValueError("Missing country code")
    provider = Provider.objects.get(code="P3")

    wanted_regions: dict[str, str] = {}
    region_allowlist = P3_REGION_ALLOWLISTS.get(country)
    for item in region_rows:
        code = str(item.get("code") or item.get("value") or "").strip()[:120]
        name = str(item.get("name") or item.get("display") or "").strip()[:160]
        if code and name and (region_allowlist is None or code in region_allowlist):
            wanted_regions[code] = name
    current_regions = {
        row.region_code: row
        for row in ProxyRegionCatalog.objects.filter(
            provider=provider, country_code=country
        )
    }
    create_regions: list[ProxyRegionCatalog] = []
    update_regions: list[ProxyRegionCatalog] = []
    for code, name in wanted_regions.items():
        row = current_regions.get(code)
        if row is None:
            create_regions.append(
                ProxyRegionCatalog(
                    provider=provider,
                    country_code=country,
                    region_code=code,
                    region_name=name,
                    source=P3_GEO_SOURCE,
                    active=True,
                )
            )
        elif row.region_name != name or row.source != P3_GEO_SOURCE or not row.active:
            row.region_name = name
            row.source = P3_GEO_SOURCE
            row.active = True
            update_regions.append(row)
    ProxyRegionCatalog.objects.bulk_create(create_regions, batch_size=1000)
    if update_regions:
        ProxyRegionCatalog.objects.bulk_update(
            update_regions, ("region_name", "source", "active"), batch_size=1000
        )
    stale_regions = ProxyRegionCatalog.objects.filter(
        provider=provider, country_code=country, active=True
    ).exclude(region_code__in=wanted_regions).update(active=False)

    wanted_cities: dict[str, str] = {}
    for item in city_rows:
        city = str(item.get("name") or item.get("value") or item.get("display") or "").strip()[:120]
        if city:
            wanted_cities[city.casefold()] = city
    current_cities = {
        row.city_name.casefold(): row
        for row in ProxyCityCatalog.objects.filter(
            provider=provider,
            account_key=P3_GEO_ACCOUNT_KEY,
            country_code=country,
            region_code="",
        )
    }
    create_cities: list[ProxyCityCatalog] = []
    update_cities: list[ProxyCityCatalog] = []
    for key, city in wanted_cities.items():
        row = current_cities.get(key)
        if row is None:
            create_cities.append(
                ProxyCityCatalog(
                    provider=provider,
                    account_key=P3_GEO_ACCOUNT_KEY,
                    country_code=country,
                    region_code="",
                    city_name=city,
                    source=P3_GEO_SOURCE,
                    active=True,
                )
            )
        elif row.city_name != city or row.source != P3_GEO_SOURCE or not row.active:
            row.city_name = city
            row.source = P3_GEO_SOURCE
            row.active = True
            update_cities.append(row)
    ProxyCityCatalog.objects.bulk_create(create_cities, batch_size=2000)
    if update_cities:
        ProxyCityCatalog.objects.bulk_update(
            update_cities, ("city_name", "source", "active"), batch_size=2000
        )
    stale_cities = ProxyCityCatalog.objects.filter(
        provider=provider,
        account_key=P3_GEO_ACCOUNT_KEY,
        country_code=country,
        region_code="",
        active=True,
    ).exclude(city_name__in=wanted_cities.values()).update(active=False)
    return (
        len(create_regions) + len(update_regions),
        stale_regions,
        len(create_cities) + len(update_cities),
        stale_cities,
    )
