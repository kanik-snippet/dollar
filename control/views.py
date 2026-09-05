from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import logging
import re
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any

from datetime import timedelta, timezone as datetime_timezone

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db.models import Prefetch, Q
from django.db import transaction
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import (
    BootstrapAudit, ClientAccess, ClientAccessIP, DesktopComponentRelease, DesktopOfficeAccessPolicy, DesktopRelease, DesktopRuntimeConfiguration, DesktopSecurityConfiguration, ExtensionPackage, ProfileActivity, ProfileDomainActivity, Provider, ProxyCountryFile,
    ProfileCreateLease, ProfileCreateQueue, ProxyCityCatalog, ProxyGenerationJob,
    ProxyPoolEntry, ProxyPoolTarget, ProxyReservation, ProxyRegionCatalog,
)
from .p3_geo_catalog import P3_GEO_ACCOUNT_KEY, p3_city_name
from .browser_catalog import current_catalog
from .geo_catalog import p2_geo_account_key_from_config
from .exit_ip_cooldown import (
    check_exit_ip,
    claim_exit_ip,
    cooldown_seconds,
    normalize_exit_ip,
)
from .release_updates import (
    component_update_manifest,
    desktop_update_manifest,
    release_applies_to_client,
    select_component_updates,
    select_desktop_update,
    verify_component_signature,
    verify_release_signature,
)


# The currently deployed desktop client still expects the server to return the
# same number of proxy reservations that it submitted.  Keep the upper bound
# at the API's normal validation limit for this diagnostic release; the client
# side cap will be reintroduced once the rebuilt EXE is deployed.
MAX_PROFILES_PER_REQUEST = 50
from .proxy_jobs import (
    get_or_create_pool_target,
    proxy_fingerprint,
    reserve_pool_proxies,
    reserve_static_proxies,
)
from .tasks import _generate, queue_refill_proxy_pool
from .inventory_alerts import record_proxy_inventory_shortage
from .openapi import OPENAPI_SCHEMA, SWAGGER_HTML
from .warrior_proxy_bridge import enabled as warrior_proxy_enabled, relay as warrior_proxy_relay


logger = logging.getLogger("control")
TOKEN_SALT = "warrior-control-catalog-v1"
LEGACY_P3_LOCATION_OFFICES = frozenset(
    {"spaze 822", "welldone 011", "mh"}
)
LEGACY_P3_LOCATION_MAX_APP_VERSION = (1, 7, 33, 9999)
P3_PREFILL_GEO_PATH = (
    Path(__file__).resolve().parent / "data" / "p3_prefill_geo.json"
)
EXACT_CITY_CANDIDATE_LIMIT = 40


def _desktop_permissions(client: ClientAccess) -> dict[str, Any]:
    return DesktopOfficeAccessPolicy.resolve_for(client)


def _provider_is_allowed(client: ClientAccess, provider_code: str) -> bool:
    code = str(provider_code or "").strip().upper()
    return bool(code and code in set(_desktop_permissions(client)["providers"]))


def _filter_desktop_providers(
    rows: list[dict[str, Any]],
    permissions: dict[str, Any],
) -> list[dict[str, Any]]:
    allowed = set(permissions["providers"])
    return [
        row for row in rows
        if str(row.get("id") or row.get("code") or "").strip().upper() in allowed
    ]


def _desktop_runtime_values(
    configured: dict[str, Any],
    permissions: dict[str, Any],
    provider_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    values = dict(configured or {})

    def options(
        key: str,
        allowed: list[str],
        fallback_names: dict[str, str],
        *,
        upper: bool,
    ) -> list[dict[str, Any]]:
        configured_rows = values.get(key)
        configured_rows = configured_rows if isinstance(configured_rows, list) else []
        known: dict[str, dict[str, Any]] = {}
        for row in configured_rows:
            if not isinstance(row, dict):
                continue
            raw_id = str(row.get("id") or "").strip()
            normalized = raw_id.upper() if upper else raw_id.lower()
            if normalized:
                known[normalized] = dict(row)
        result = []
        for index, raw_id in enumerate(allowed):
            normalized = raw_id.upper() if upper else raw_id.lower()
            row = known.get(normalized, {
                "id": normalized,
                "name": fallback_names.get(normalized, normalized),
            })
            row["id"] = normalized
            row["enabled"] = True
            row["order"] = index + 1
            result.append(row)
        return result

    provider_names = {
        str(row.get("id") or row.get("code") or "").strip().upper():
        str(row.get("name") or row.get("label") or row.get("id") or row.get("code") or "")
        for row in provider_rows
    }
    values["providers"] = options(
        "providers", permissions["providers"], provider_names, upper=True
    )
    values["browsers"] = options(
        "browsers",
        permissions["browsers"],
        {"B1": "B1", "B2": "B2 — Octo One-Time"},
        upper=True,
    )
    values["devices"] = options(
        "devices",
        permissions["devices"],
        {"desktop": "Desktop", "mobile": "Mobile"},
        upper=False,
    )
    features = dict(values.get("features") or {})
    features["showLogs"] = bool(permissions["show_logs"])
    values["features"] = features
    access_policy = {
        "source": permissions["source"],
        "officeName": permissions["office_name"],
    }
    values["accessPolicy"] = access_policy
    # Older installed shells only expose the generic ``runtime`` object to a
    # hot UI component. Mirror permission metadata there so Logs visibility
    # can roll out without requiring a new installer.
    runtime = dict(values.get("runtime") or {})
    runtime_features = dict(runtime.get("features") or {})
    runtime_features["showLogs"] = bool(permissions["show_logs"])
    runtime["features"] = runtime_features
    runtime["accessPolicy"] = access_policy
    values["runtime"] = runtime
    return values


@lru_cache(maxsize=1)
def _p3_prefill_geography() -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(P3_PREFILL_GEO_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        logger.exception("Could not load the bundled P3 geography catalog")
        return {}
    return payload if isinstance(payload, dict) else {}


def _app_version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(value or ""))
    return tuple(int(part) for part in parts[:4])


def _desktop_product(value: str, app_version: str, activation_key: str) -> str:
    reported = str(value or "").strip().casefold()
    if reported in {ClientAccess.DESKTOP_PRODUCT_DOLLAR, ClientAccess.DESKTOP_PRODUCT_LEGACY}:
        return reported
    if activation_key:
        return ClientAccess.DESKTOP_PRODUCT_DOLLAR
    parsed = _app_version_tuple(app_version)
    if parsed and parsed[:2] >= (1, 7):
        return ClientAccess.DESKTOP_PRODUCT_LEGACY
    if parsed:
        return ClientAccess.DESKTOP_PRODUCT_DOLLAR
    return ClientAccess.DESKTOP_PRODUCT_UNKNOWN


def _legacy_p3_location_catalog(
    client: ClientAccess,
    app_version: str,
    update_protocol: int = 0,
) -> bool:
    # Dollar speaks the structured component-update protocol and has dedicated
    # country/region/city controls. Its product version overlaps the legacy
    # desktop range, so version-only detection would flatten locations into
    # the Country select and truncate the list.
    if int(update_protocol or 0) >= 2:
        return False
    if str(client.office_name or "").strip().casefold() not in LEGACY_P3_LOCATION_OFFICES:
        return False
    parsed = _app_version_tuple(app_version)
    return not parsed or parsed <= LEGACY_P3_LOCATION_MAX_APP_VERSION


def _legacy_p3_location_id(kind: str, country_code: str, value: str) -> str:
    prefix = "P3R" if kind == "region" else "P3C"
    country = str(country_code or "").strip().upper()
    digest = hashlib.sha256(
        f"{kind}\0{country}\0{value}".encode("utf-8")
    ).hexdigest()[:24]
    return f"{prefix}_{country}_{digest}"


@lru_cache(maxsize=1)
def _legacy_p3_location_aliases() -> dict[str, tuple[str, str, str]]:
    aliases: dict[str, tuple[str, str, str]] = {}
    for country_code, details in _p3_prefill_geography().items():
        country = str(country_code or "").strip().upper()
        for region in details.get("regions", []):
            code = str(region.get("code") or "").strip()
            if code:
                aliases[_legacy_p3_location_id("region", country, code)] = (
                    country,
                    code,
                    "",
                )
        for city in details.get("cities", []):
            city_name = str(city or "").strip()
            if city_name:
                aliases[_legacy_p3_location_id("city", country, city_name)] = (
                    country,
                    "",
                    city_name,
                )
    return aliases


def _legacy_p3_location_rows(
    country_files: list[ProxyCountryFile],
) -> list[dict[str, Any]]:
    geography = _p3_prefill_geography()
    rows: list[dict[str, Any]] = []
    for country in country_files:
        base = {
            "id": country.country_code,
            "name": country.country_name,
            "version": country.version,
            "sha256": country.content_sha256,
            "regions": [],
        }
        rows.append(base)
        details = geography.get(country.country_code, {})
        for region in details.get("regions", []):
            code = str(region.get("code") or "").strip()
            name = str(region.get("name") or "").strip()
            if code and name:
                rows.append(
                    {
                        **base,
                        "id": _legacy_p3_location_id(
                            "region",
                            country.country_code,
                            code,
                        ),
                        "name": f"{country.country_name} - STATE - {name}",
                    }
                )
        for city in details.get("cities", []):
            city_name = str(city or "").strip()
            if city_name and "|" not in city_name:
                rows.append(
                    {
                        **base,
                        "id": _legacy_p3_location_id(
                            "city",
                            country.country_code,
                            city_name,
                        ),
                        "name": f"{country.country_name} - CITY - {city_name}",
                    }
                )
    return rows


def _decode_p3_legacy_location(
    provider_code: str,
    raw_country: str,
    region: str,
    city: str,
) -> tuple[str, str, str]:
    raw = str(raw_country or "").strip()
    if provider_code != "P3" or not raw.startswith(("P3R_", "P3C_")):
        country_code = raw.upper()
        return ("GB" if country_code == "UK" else country_code, region, city)
    aliases = _legacy_p3_location_aliases()
    decoded = aliases.get(raw)
    if decoded is None:
        # Some desktop clients normalize select values to upper-case.
        parts = raw.split("_", 2)
        if len(parts) == 3:
            canonical = f"{parts[0].upper()}_{parts[1].upper()}_{parts[2].lower()}"
            decoded = aliases.get(canonical)
    if decoded is None:
        raise ValueError("Unsupported legacy P3 location")
    return decoded


def _json_response(payload: dict[str, Any], status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _normalized_ip(value: Any) -> str:
    parsed = ipaddress.ip_address(str(value or "").strip())
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    return str(parsed)


def observed_client_ip(request: HttpRequest) -> str:
    if settings.TRUST_PROXY_HEADERS:
        origin_secret = settings.CLOUDFLARE_ORIGIN_SECRET
        if origin_secret:
            supplied_secret = request.META.get(
                "HTTP_X_TUBELIGHT_ORIGIN_SECRET", ""
            )
            if not hmac.compare_digest(supplied_secret, origin_secret):
                raise ValueError("Untrusted origin request")
            cloudflare_ip = request.META.get("HTTP_CF_CONNECTING_IP", "")
            if not cloudflare_ip:
                raise ValueError("Cloudflare client IP missing")
            return _normalized_ip(cloudflare_ip)

        # Local/legacy deployments without the Cloudflare origin secret keep
        # the normal reverse-proxy fallbacks. Production kanikdev.xyz should
        # always configure the secret so spoofed IP headers are rejected.
        real_ip = request.META.get("HTTP_X_REAL_IP", "")
        if real_ip:
            return _normalized_ip(real_ip)
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return _normalized_ip(forwarded.split(",", 1)[0])
    return _normalized_ip(request.META.get("REMOTE_ADDR", ""))


def _rate_limited(ip_value: str) -> bool:
    limit = max(1, settings.BOOTSTRAP_RATE_LIMIT_PER_MINUTE)
    key = f"bootstrap-rate:{ip_value}:{int(timezone.now().timestamp()) // 60}"
    try:
        if cache.add(key, 1, timeout=75):
            return False
        return cache.incr(key) > limit
    except Exception:
        # Redis is an optimization for rate limiting, not a prerequisite for
        # application authorization.  A cache outage (including Redis MISCONF
        # after a failed RDB snapshot) must never turn bootstrap into HTTP 500.
        logger.warning("Bootstrap rate-limit cache unavailable; allowing request")
        return False


def _audit(
    *,
    observed_ip: str | None,
    reported_ip: str | None,
    allowed: bool,
    reason: str,
    app_version: str,
    device_id: str = "",
    client: ClientAccess | None = None,
) -> None:
    try:
        BootstrapAudit.objects.create(
            client=client,
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            device_id=device_id[:128],
            allowed=allowed,
            reason=reason[:80],
            app_version=app_version[:40],
        )
    except Exception:
        logger.exception("Could not write bootstrap audit event")


def _denied(
    reason: str,
    *,
    observed_ip: str | None = None,
    reported_ip: str | None = None,
    app_version: str = "",
    device_id: str = "",
    client: ClientAccess | None = None,
    status: int = 403,
) -> JsonResponse:
    _audit(
        observed_ip=observed_ip,
        reported_ip=reported_ip,
        allowed=False,
        reason=reason,
        app_version=app_version,
        device_id=device_id,
        client=client,
    )
    return _json_response(
        {"allowed": False, "message": "Access denied."},
        status=status,
    )


def _bootstrap_client(device_id: str, access_ip: str) -> ClientAccess | None:
    """Resolve normal clients by device+IP and trusted bypass clients by device.

    A bypass is an explicit administrator decision for one stable Device ID.
    Its public IPv4 may change, so requiring every new address to be manually
    approved would make the bypass ineffective.
    """
    rows = ClientAccess.objects.select_related("config_bundle").filter(
        device_id=device_id
    )
    bypass = (
        rows.filter(
            active=True,
            config_bundle__active=True,
            activation_mode=ClientAccess.ACTIVATION_BYPASS,
        )
        .order_by("pk")
        .first()
    )
    if bypass is not None:
        return bypass
    exact = (
        rows.filter(
            Q(ipv4=access_ip)
            | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        )
        .distinct()
        .order_by("pk")
        .first()
    )
    if exact is not None:
        return exact
    return None


def _remember_bypass_ip(client: ClientAccess, access_ip: str) -> None:
    if (
        client.activation_mode != ClientAccess.ACTIVATION_BYPASS
        or client.ipv4 == access_ip
    ):
        return
    ClientAccessIP.objects.update_or_create(
        client=client,
        ipv4=access_ip,
        defaults={"active": True},
    )


def _catalog(*, flatten_p3_locations: bool = False) -> list[dict[str, Any]]:
    active_files = ProxyCountryFile.objects.filter(active=True).only(
        "provider_id", "country_code", "country_name", "version", "content_sha256"
    )
    active_regions = ProxyRegionCatalog.objects.filter(active=True).only(
        "provider_id", "country_code", "region_code", "region_name"
    )
    providers = Provider.objects.filter(active=True).prefetch_related(
        Prefetch("country_files", queryset=active_files),
        Prefetch("region_catalog", queryset=active_regions),
    )
    result: list[dict[str, Any]] = []
    for provider in providers:
        country_files = list(provider.country_files.all())
        if not country_files:
            continue
        regions_by_country: dict[str, list[dict[str, str]]] = {}
        if provider.code in {"P1", "P2", "P3", "P4"}:
            for region in provider.region_catalog.all():
                regions_by_country.setdefault(region.country_code, []).append(
                    {
                        "id": region.region_code,
                        "name": region.region_name,
                    }
                )
        countries = [
            {
                "id": row.country_code,
                "name": row.country_name,
                "version": row.version,
                "sha256": row.content_sha256,
                "regions": regions_by_country.get(row.country_code, []),
            }
            for row in country_files
        ]
        if provider.code == "P3" and flatten_p3_locations:
            countries = _legacy_p3_location_rows(country_files)
        result.append({
            "id": provider.code,
            "name": provider.display_name,
            "countries": countries,
        })
    return result


def _desktop_catalog(
    client: ClientAccess,
    *,
    flatten_p3_locations: bool = False,
) -> list[dict[str, Any]]:
    """Use Warrior's signed catalog when this Dollar server delegates proxies."""
    local_catalog = _catalog(flatten_p3_locations=flatten_p3_locations)
    if not warrior_proxy_enabled():
        return local_catalog
    response = warrior_proxy_relay(client, "catalog")
    if response.status_code >= 400:
        logger.warning("Warrior provider catalog relay failed with status %s", response.status_code)
        return local_catalog
    try:
        payload = json.loads(response.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Warrior provider catalog relay returned invalid JSON")
        return local_catalog
    providers = payload.get("providers") if isinstance(payload, dict) else None
    return providers if isinstance(providers, list) and providers else local_catalog


@require_GET
def home(request: HttpRequest) -> HttpResponse:
    return render(request, "control/home.html")


@require_GET
def healthz(_request: HttpRequest) -> JsonResponse:
    return _json_response({"ok": True})


@require_GET
def openapi_schema(_request: HttpRequest) -> JsonResponse:
    return JsonResponse(OPENAPI_SCHEMA)


@require_GET
def swagger_docs(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(SWAGGER_HTML, content_type="text/html; charset=utf-8")


@require_GET
def public_ipv4(request: HttpRequest) -> JsonResponse:
    try:
        observed_ip = observed_client_ip(request)
        if ipaddress.ip_address(observed_ip).version != 4:
            raise ValueError("IPv4 required")
    except ValueError:
        return _json_response(
            {"ok": False, "message": "IPv4 unavailable."},
            status=400,
        )
    return _json_response({"ok": True, "ipv4": observed_ip})


@csrf_exempt
@require_POST
def bootstrap(request: HttpRequest) -> JsonResponse:
    observed_ip: str | None = None
    reported_ip: str | None = None
    app_version = ""
    device_id = ""
    app_build = 0
    app_channel = ""
    update_protocol = 0
    activation_key = ""
    activation_revision = 0
    client_product = ""
    try:
        if settings.TRUST_APP_REPORTED_IPV4:
            # In approved app-reported mode the transport address is audit-only.
            # Do not require Cloudflare headers: the custom domain may be DNS-only.
            observed_ip = _normalized_ip(request.META.get("REMOTE_ADDR", ""))
        else:
            observed_ip = observed_client_ip(request)
        if ipaddress.ip_address(observed_ip).version != 4:
            return _denied("ipv4-required", observed_ip=observed_ip)
        body = json.loads(request.body.decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        reported_ip = _normalized_ip(body.get("reported_ipv4"))
        app_version = str(body.get("app_version") or "")
        device_id = str(body.get("device_id") or "").strip()[:128]
        app_build = int(body.get("app_build") or 0)
        app_channel = str(body.get("app_channel") or "").strip()[:16]
        update_protocol = int(body.get("update_protocol") or 0)
        activation_key = str(body.get("activation_key") or "").strip()[:512]
        activation_revision = int(body.get("activation_revision") or 0)
        client_product = str(body.get("client_product") or "").strip()[:16]
        if (
            app_build < 0
            or app_build > 9_223_372_036_854_775_807
            or update_protocol < 0
            or update_protocol > 1_000
            or activation_revision < 0
            or activation_revision > 9_223_372_036_854_775_807
        ):
            raise ValueError("Update metadata must be non-negative")
        if ipaddress.ip_address(reported_ip).version != 4:
            return _denied(
                "reported-ipv4-required",
                observed_ip=observed_ip,
                reported_ip=reported_ip,
                app_version=app_version,
            )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return _denied(
            "invalid-request",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            status=400,
        )

    access_ip = (
        reported_ip if settings.TRUST_APP_REPORTED_IPV4 else observed_ip
    )
    # Rate-limit each authorized device independently. Multiple office PCs
    # commonly share the same public/NAT IP and must not consume one quota.
    rate_key = f"{observed_ip}:{access_ip}:{device_id or '<no-device-id>'}"
    if _rate_limited(rate_key):
        return _denied(
            "rate-limited",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            status=429,
        )
    if (
        not settings.TRUST_APP_REPORTED_IPV4
        and settings.REQUIRE_REPORTED_IP_MATCH
        and reported_ip != observed_ip
    ):
        return _denied(
            "ip-mismatch",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
        )

    if settings.LOCAL_TESTING_MODE:
        # The local test server is bound to loopback and intentionally uses its
        # first active client/config as a disposable sandbox.  This avoids
        # copying production device/IP allow-list data into the local SQLite DB.
        client = (
            ClientAccess.objects.select_related("config_bundle")
            .filter(active=True, config_bundle__active=True)
            .order_by("pk")
            .first()
        )
    else:
        client = _bootstrap_client(device_id, access_ip)
    if client is None:
        return _denied(
            "not-whitelisted",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
        )
    if not client.active or not client.config_bundle.active:
        return _denied(
            "inactive",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            client=client,
        )

    _remember_bypass_ip(client, access_ip)

    security = DesktopSecurityConfiguration.objects.filter(pk=1).first()
    activation_is_required = _activation_is_required(client, security)
    if activation_is_required:
        if not security.check_activation_key(activation_key):
            first_activation = not activation_key
            reason = "activation-required" if first_activation else "activation-expired"
            _audit(
                observed_ip=observed_ip,
                reported_ip=reported_ip,
                allowed=False,
                reason=reason,
                app_version=app_version,
                device_id=device_id,
                client=client,
            )
            return _json_response(
                {
                    "allowed": False,
                    "code": "activation_expired",
                    "message": (
                        "Enter the activation key provided by your Dollar administrator to activate this installation."
                        if first_activation
                        else "Activation Expired. Reactivate again. Contact your Admin."
                    ),
                    "activation": {
                        "required": True,
                        "revision": int(security.activation_revision),
                    },
                },
                status=403,
            )

    try:
        config = client.config_bundle.get_payload()
    except ValueError:
        logger.exception("Configuration decryption failed for bundle %s", client.config_bundle_id)
        return _denied(
            "config-unavailable",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            client=client,
            status=503,
        )

    group_id = client.config_bundle.browser_group_id.strip()
    group_name = client.config_bundle.browser_group_name.strip() or "Testing"
    profile_name = client.profile_name.strip() or client.name.strip()
    config["OFFICE_NAME"] = client.office_name
    config["SYSTEM_NUMBER"] = client.system_number
    config["BROWSER_GROUP_ID"] = group_id
    config["BROWSER_GROUP_NAME"] = group_name
    config["DEVICE_PROFILE_NAME"] = profile_name
    token_payload = {
        "client_id": client.pk,
        "ip": access_ip,
        "ip_source": (
            "app-reported" if settings.TRUST_APP_REPORTED_IPV4 else "observed"
        ),
        "device_id": device_id,
        "config_version": client.config_bundle.version,
        "activation_revision": (
            int(security.activation_revision)
            if activation_is_required and security is not None
            else 0
        ),
        "activation_enforced": activation_is_required,
    }
    token = signing.dumps(token_payload, salt=TOKEN_SALT, compress=True)
    detected_product = _desktop_product(client_product, app_version, activation_key)
    detected_activation_revision = 0
    if (
        detected_product == ClientAccess.DESKTOP_PRODUCT_DOLLAR
        and security is not None
        and activation_key
        and security.check_activation_key(activation_key)
    ):
        detected_activation_revision = int(security.activation_revision)
    ClientAccess.objects.filter(pk=client.pk).update(
        last_seen_at=timezone.now(),
        desktop_client_product=detected_product,
        desktop_client_version=app_version[:40],
        desktop_client_detected_at=timezone.now(),
        desktop_activation_revision=detected_activation_revision,
    )
    _audit(
        observed_ip=observed_ip,
        reported_ip=reported_ip,
        allowed=True,
        reason="allowed",
        app_version=app_version,
        device_id=device_id,
        client=client,
    )
    desktop_permissions = _desktop_permissions(client)
    desktop_provider_rows = _filter_desktop_providers(
        _desktop_catalog(
            client,
            flatten_p3_locations=_legacy_p3_location_catalog(
                client,
                app_version,
                update_protocol,
            )
        ),
        desktop_permissions,
    )
    response_payload = {
        "allowed": True,
        "schema_version": 1,
        "config_version": client.config_bundle.version,
        "expires_in": settings.BOOTSTRAP_TOKEN_MAX_AGE,
        "access_token": token,
        "tubelight_config": config,
        "assignment": {
            "browser_group_id": group_id,
            "browser_group_name": group_name,
            "profile_name": profile_name,
        },
        "desktop_permissions": desktop_permissions,
        "catalog": {"providers": desktop_provider_rows, "extensions": [
            {"id": item.pk, "name": item.name, "filename": item.filename,
             "version": item.version, "sha256": item.package_sha256,
             "is_top": item.is_top, "status": item.status}
            for item in ExtensionPackage.objects.exclude(package_ciphertext="")
        ]},
    }
    if (
        client.desktop_remote_action == ClientAccess.REMOTE_ACTION_UNINSTALL
        and client.desktop_remote_action_acknowledged_at is None
    ):
        response_payload["desktop_command"] = {
            "action": ClientAccess.REMOTE_ACTION_UNINSTALL,
            "revision": int(client.desktop_remote_action_revision),
            "requested_at": client.desktop_remote_action_requested_at.isoformat()
            if client.desktop_remote_action_requested_at
            else None,
        }
    desktop_security = {
        "activation": {
            "required": activation_is_required,
            "valid": True,
            "revision": int(security.activation_revision) if security else 0,
        },
        "browsers": {
            "B1": {
                "enabled": False,
                "revision": int(security.b1_revision) if security else 0,
            }
        },
    }
    if (
        "B1" in desktop_permissions["browsers"]
        and security is not None
        and security.b1_enabled
    ):
        try:
            b1_key = security.get_b1_key()
        except ValueError:
            logger.exception("Could not decrypt the global B1 bridge key")
            b1_key = ""
        if b1_key:
            desktop_security["browsers"]["B1"].update(
                {"enabled": True, "api_key": b1_key}
            )
    response_payload["desktop_security"] = desktop_security
    runtime_config = DesktopRuntimeConfiguration.objects.filter(
        channel=client.release_channel,
        active=True,
    ).first()
    runtime_values = _desktop_runtime_values(
        runtime_config.ui_config if runtime_config is not None else {},
        desktop_permissions,
        desktop_provider_rows,
    )
    response_payload["desktop_runtime_config"] = {
        "revision": int(runtime_config.revision) if runtime_config is not None else 0,
        "values": runtime_values,
    }
    if detected_product == "dollar":
        catalog = current_catalog(descriptor=True)
        if catalog is not None:
            response_payload["browser_catalog_sync"] = catalog
    if update_protocol >= 1:
        # ClientAccess remains authoritative, and a mismatched executable gets
        # no manifest instead of a manifest it would reject for another channel.
        release = None
        if app_channel == client.release_channel:
            release = select_desktop_update(client=client, app_build=app_build)
        response_payload["desktop_update"] = (
            desktop_update_manifest(release) if release is not None else None
        )
    if update_protocol >= 2:
        response_payload["desktop_components"] = [
            component_update_manifest(item)
            for item in select_component_updates(client=client)
        ]
    return _json_response(response_payload)


@csrf_exempt
@require_POST
def desktop_command_ack(request: HttpRequest) -> JsonResponse:
    """Acknowledge a server-issued desktop command before local execution."""
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8") or "{}")
        action = str(body.get("action") or "").strip().lower()
        revision = int(body.get("revision") or 0)
        if (
            action != ClientAccess.REMOTE_ACTION_UNINSTALL
            or client.desktop_remote_action != action
            or revision != int(client.desktop_remote_action_revision)
            or client.desktop_remote_action_acknowledged_at is not None
        ):
            raise ValueError("Desktop command is no longer pending")
        now = timezone.now()
        ClientAccess.objects.filter(pk=client.pk).update(
            desktop_remote_action_acknowledged_at=now,
            updated_at=now,
        )
    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
    ):
        return _json_response({"ok": False, "message": "Desktop command acknowledgement denied."}, status=403)
    return _json_response({"ok": True, "action": action, "revision": revision})


def _bearer_token(request: HttpRequest) -> str:
    authorization = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise ValueError("Missing bearer token")
    return value.strip()


def _validate_activation_revision(token_payload: dict[str, Any]) -> None:
    """Invalidate all existing bearer tokens immediately after activation rotates."""
    if not bool(token_payload.get("activation_enforced")):
        return
    security = DesktopSecurityConfiguration.objects.filter(pk=1).only(
        "activation_required", "activation_revision"
    ).first()
    if security is None or not security.activation_required:
        return
    if int(token_payload.get("activation_revision") or 0) != int(security.activation_revision):
        raise signing.BadSignature("Activation changed")


def _activation_is_required(
    client: ClientAccess,
    security: DesktopSecurityConfiguration | None,
) -> bool:
    """Apply OPTIX activation only to public-channel client access records."""
    # Testing is deliberately never activation-gated.  This keeps the legacy
    # testing app and test rollout channel usable while Public installations
    # can be enforced independently.
    if client.release_channel == ClientAccess.RELEASE_CHANNEL_TESTING:
        return False
    if security is None or not security.activation_key_hash:
        return False
    mode = str(client.activation_mode or ClientAccess.ACTIVATION_INHERIT)
    if mode == ClientAccess.ACTIVATION_BYPASS:
        return False
    if mode == ClientAccess.ACTIVATION_REQUIRE:
        return True
    return bool(security.activation_required)


@require_GET
def proxy_file(request: HttpRequest, provider_code: str, country_code: str) -> JsonResponse:
    try:
        if settings.TRUST_APP_REPORTED_IPV4:
            observed_ip = _normalized_ip(request.META.get("REMOTE_ADDR", ""))
        else:
            observed_ip = observed_client_ip(request)
        device_id = str(request.META.get("HTTP_X_DEVICE_ID", "")).strip()[:128]
        if settings.TRUST_APP_REPORTED_IPV4:
            access_ip = _normalized_ip(
                request.META.get("HTTP_X_CLIENT_IPV4", "")
            )
            if ipaddress.ip_address(access_ip).version != 4:
                raise ValueError("Client IPv4 required")
        else:
            access_ip = observed_ip
        token_payload = signing.loads(
            _bearer_token(request),
            salt=TOKEN_SALT,
            max_age=settings.BOOTSTRAP_TOKEN_MAX_AGE,
        )
        if token_payload.get("ip") != access_ip:
            raise signing.BadSignature("IP changed")
        if token_payload.get("device_id", "") != device_id:
            raise signing.BadSignature("Device changed")
        _validate_activation_revision(token_payload)
        client = ClientAccess.objects.select_related("config_bundle").filter(
            pk=token_payload.get("client_id"),
            device_id=device_id,
            active=True,
            config_bundle__active=True,
        ).filter(
            Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        ).distinct().get()
        if token_payload.get("config_version") != client.config_bundle.version:
            raise signing.BadSignature("Configuration changed")
        if not _provider_is_allowed(client, provider_code):
            raise ValueError("Provider access denied")
        row = ProxyCountryFile.objects.select_related("provider").get(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            active=True,
        )
        content = row.get_content()
    except (
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
        ProxyCountryFile.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."},
            status=403,
        )
    return _json_response(
        {
            "allowed": True,
            "provider": row.provider.code,
            "country": row.country_code,
            "version": row.version,
            "sha256": row.content_sha256,
            "content": content,
        }
    )


def _authenticated_client(request: HttpRequest) -> ClientAccess:
    """Validate the short-lived, IP and device-bound bootstrap token."""
    if settings.TRUST_APP_REPORTED_IPV4:
        access_ip = _normalized_ip(request.META.get("HTTP_X_CLIENT_IPV4", ""))
        if ipaddress.ip_address(access_ip).version != 4:
            raise ValueError("Client IPv4 required")
    else:
        access_ip = observed_client_ip(request)
    device_id = str(request.META.get("HTTP_X_DEVICE_ID", "")).strip()[:128]
    token_payload = signing.loads(_bearer_token(request), salt=TOKEN_SALT,
                                  max_age=settings.BOOTSTRAP_TOKEN_MAX_AGE)
    if token_payload.get("ip") != access_ip or token_payload.get("device_id", "") != device_id:
        raise signing.BadSignature("Client identity changed")
    _validate_activation_revision(token_payload)
    client_query = ClientAccess.objects.select_related("config_bundle").filter(
        pk=token_payload.get("client_id"), active=True, config_bundle__active=True,
    )
    if not settings.LOCAL_TESTING_MODE:
        client_query = client_query.filter(device_id=device_id).filter(
            Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        ).distinct()
    client = client_query.get()
    if token_payload.get("config_version") != client.config_bundle.version:
        raise signing.BadSignature("Configuration changed")
    return client


def _proxy_protocol(value: str) -> str:
    prefix = str(value or "").strip().partition("://")[0].casefold()
    if "://" not in str(value or ""):
        return ""
    return {
        "http": "http",
        "https": "https",
        "socks5": "socks5",
        "socks5h": "socks5",
    }.get(prefix, "")


def _profile_lease_key(client: ClientAccess, group_id: str) -> str:
    """Return an account-and-group scoped key without storing the API key."""
    try:
        payload = client.config_bundle.get_payload()
    except Exception:
        payload = {}
    account_key = str(
        payload.get("APP_API_KEY")
        or payload.get("YSBROWSER_API_KEY")
        or payload.get("API_KEY")
        or ""
    ).strip()
    if account_key:
        account_scope = hashlib.sha256(account_key.encode("utf-8")).hexdigest()[:32]
    else:
        account_scope = f"bundle-{client.config_bundle_id}"
    return f"profile-create:{account_scope}:{group_id.strip()}"


def _lease_group_allowed(client: ClientAccess, group_id: str) -> bool:
    assigned = str(client.config_bundle.browser_group_id or "").strip()
    return bool(group_id and (not assigned or assigned == group_id))


@csrf_exempt
@require_POST
def acquire_profile_lease(request: HttpRequest) -> JsonResponse:
    """Join a FIFO queue and atomically reserve one YS group for a run."""
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        group_id = str(body.get("group_id") or "").strip()[:64]
        requested_count = min(50, max(1, int(body.get("requested_count") or 1)))
        request_token = str(body.get("request_token") or "").strip()[:96]
        if not _lease_group_allowed(client, group_id):
            raise ValueError("Invalid browser group assignment")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    if not settings.PROFILE_CREATE_SERIALIZATION_ENABLED:
        # Each production device owns a distinct browser group. Keeping a FIFO
        # lease in that topology only allows an abandoned row to block its own
        # device. Expire legacy rows and authorize creation immediately.
        key = _profile_lease_key(client, group_id)
        now = timezone.now()
        ProfileCreateLease.objects.filter(lease_key=key).delete()
        ProfileCreateQueue.objects.filter(
            scope_key=key,
            status__in=("queued", "active"),
        ).update(status="expired", lease_token="", expires_at=now)
        return _json_response(
            {
                "allowed": True,
                "queued": False,
                "lease_id": f"direct-{secrets.token_urlsafe(32)}",
                "group_id": group_id,
                "lease_seconds": 0,
                "serialized": False,
            }
        )

    # Five minutes covers proxy polling plus the YS add/list/open sequence;
    # a crashed process is released automatically after this deadline.
    lease_seconds = 300
    queue_seconds = 43200
    now = timezone.now()
    expires_at = now + timedelta(seconds=lease_seconds)
    queue_expires_at = now + timedelta(seconds=queue_seconds)
    key = _profile_lease_key(client, group_id)
    with transaction.atomic():
        ProfileCreateQueue.objects.filter(
            scope_key=key, status="queued", expires_at__lte=now,
        ).update(status="expired")
        if request_token:
            try:
                queue = ProfileCreateQueue.objects.select_for_update().get(
                    request_token=request_token, scope_key=key, client=client,
                )
            except ProfileCreateQueue.DoesNotExist:
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
            if queue.status in {"completed", "expired"}:
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
            if queue.status == "active" and queue.lease_token:
                lease = ProfileCreateLease.objects.filter(
                    lease_key=key, owner_token=queue.lease_token,
                ).first()
                if lease and lease.expires_at > now:
                    return _json_response({"allowed": True, "lease_id": lease.owner_token, "group_id": group_id, "lease_seconds": lease_seconds})
                # This request already owned a lease and then stopped renewing
                # it.  Re-queuing the old row at its original FIFO position
                # leaves a dead request at the head for up to twelve hours.
                # Expire it and make the caller submit a fresh request instead.
                if lease:
                    lease.delete()
                queue.status = "expired"
                queue.lease_token = ""
                queue.expires_at = now
                queue.save(update_fields=("status", "lease_token", "expires_at", "updated_at"))
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
        else:
            # A desktop retry supersedes its own abandoned queued request. A
            # crashed/closed app must not leave an invisible FIFO blocker for
            # the same device and group until the long queue expiry.
            ProfileCreateQueue.objects.filter(
                scope_key=key,
                client=client,
                status="queued",
            ).update(status="expired", expires_at=now)
            queue = ProfileCreateQueue.objects.create(
                scope_key=key,
                request_token=secrets.token_urlsafe(48),
                client=client,
                group_id=group_id,
                requested_count=requested_count,
                status="queued",
                expires_at=queue_expires_at,
            )

        lease = ProfileCreateLease.objects.select_for_update().filter(lease_key=key).first()
        if lease and lease.expires_at <= now:
            # A crashed client must leave the queue completely.  Re-queuing its
            # active row creates a permanent FIFO blocker because that client
            # will never poll its request token again.
            ProfileCreateQueue.objects.filter(
                scope_key=key, status="active", lease_token=lease.owner_token,
            ).update(status="expired", lease_token="", expires_at=now)
            lease.delete()
            lease = None

        head = ProfileCreateQueue.objects.select_for_update().filter(
            scope_key=key, status="queued", expires_at__gt=now,
        ).order_by("created_at", "pk").first()
        if lease or not head or head.pk != queue.pk:
            position = 1
            if head and head.pk != queue.pk:
                position = 1 + ProfileCreateQueue.objects.filter(
                    scope_key=key, status="queued", expires_at__gt=now,
                    created_at__lt=queue.created_at,
                ).count()
            return _json_response({
                "allowed": False,
                "queued": True,
                "request_token": queue.request_token,
                "position": position,
                "retry_after": 5,
                "message": "Your profile request is queued for this browser group.",
                "group_id": group_id,
            })

        owner_token = secrets.token_urlsafe(48)
        lease = ProfileCreateLease.objects.create(
            lease_key=key,
            owner_token=owner_token,
            client=client,
            group_id=group_id,
            requested_count=queue.requested_count,
            expires_at=expires_at,
        )
        queue.status = "active"
        queue.lease_token = owner_token
        queue.expires_at = expires_at
        queue.save(update_fields=("status", "lease_token", "expires_at", "updated_at"))
    return _json_response({
        "allowed": True,
        "lease_id": lease.owner_token,
        "group_id": group_id,
        "lease_seconds": lease_seconds,
    })


@csrf_exempt
@require_POST
def release_profile_lease(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        group_id = str(body.get("group_id") or "").strip()[:64]
        lease_id = str(body.get("lease_id") or "").strip()[:96]
        request_token = str(body.get("request_token") or "").strip()[:96]
        if (not lease_id and not request_token) or not _lease_group_allowed(client, group_id):
            raise ValueError("Invalid profile lease")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    if not settings.PROFILE_CREATE_SERIALIZATION_ENABLED:
        return _json_response(
            {
                "allowed": True,
                "released": True,
                "cancelled": bool(request_token and not lease_id),
                "serialized": False,
            }
        )
    key = _profile_lease_key(client, group_id)
    if request_token and not lease_id:
        cancelled = ProfileCreateQueue.objects.filter(
            scope_key=key,
            request_token=request_token,
            client=client,
            status="queued",
        ).update(status="expired", expires_at=timezone.now())
        return _json_response(
            {"allowed": bool(cancelled), "released": False, "cancelled": bool(cancelled)}
        )
    deleted, _ = ProfileCreateLease.objects.filter(
        lease_key=key, owner_token=lease_id, client=client,
    ).delete()
    ProfileCreateQueue.objects.filter(
        scope_key=key, lease_token=lease_id, client=client,
    ).update(status="completed", lease_token="")
    return _json_response({"allowed": bool(deleted), "released": bool(deleted)})


def _job_payload(job: ProxyGenerationJob) -> dict[str, Any]:
    reservations = job.reservations.order_by("reserved_at", "pk")
    proxies = []
    for item in reservations:
        value = item.get_proxy()
        proxies.append({
            "reservation_id": item.pk,
            "proxy": value,
            "protocol": _proxy_protocol(value),
            "provider": item.provider_code,
            "country": item.country_code,
            "region": item.region,
            "city": item.city,
        })
    return {
        "id": job.pk,
        "status": job.status,
        "submitted_count": job.submitted_count,
        "requested_count": job.requested_count,
        "candidate_count": max(
            int(job.requested_count),
            int(getattr(job, "candidate_count", 1) or 1),
        ),
        "max_profiles_per_request": MAX_PROFILES_PER_REQUEST,
        "was_capped": job.submitted_count > job.requested_count,
        "ready_count": job.ready_count,
        "error": job.error,
        "proxies": proxies,
    }


@require_GET
def extension_package(request: HttpRequest, package_id: int) -> HttpResponse:
    try:
        _authenticated_client(request)
        package = ExtensionPackage.objects.get(pk=package_id)
        raw = package.get_package()
        if not raw:
            raise ExtensionPackage.DoesNotExist
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist, ExtensionPackage.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    response = HttpResponse(raw, content_type="application/zip")
    response["Content-Disposition"] = f'attachment; filename="{package.filename}"'
    response["X-Content-SHA256"] = package.package_sha256
    response["Cache-Control"] = "no-store"
    return response


@require_GET
def desktop_release_download(request: HttpRequest, release_id: int) -> HttpResponse:
    try:
        client = _authenticated_client(request)
        release = DesktopRelease.objects.get(
            pk=release_id,
            status=DesktopRelease.STATUS_PUBLISHED,
            channel=client.release_channel,
        )
        if not release_applies_to_client(release, client):
            raise DesktopRelease.DoesNotExist
        verify_release_signature(release)
        if not release.artifact:
            raise DesktopRelease.DoesNotExist
        release.artifact.open("rb")
    except (
        OSError,
        ValidationError,
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
        DesktopRelease.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."},
            status=403,
        )

    filename = (
        release.original_filename.replace("\\", "/").rsplit("/", 1)[-1]
        or f"quest-automation-{release.version}.exe"
    )
    response = FileResponse(
        release.artifact,
        as_attachment=True,
        filename=filename,
        content_type="application/vnd.microsoft.portable-executable",
    )
    response["Content-Length"] = str(release.artifact_size)
    response["X-Content-SHA256"] = release.artifact_sha256
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_GET
def desktop_component_manifest(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
    except (
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
    ):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    return _json_response(
        {
            "allowed": True,
            "schema_version": 1,
            "components": [
                component_update_manifest(item)
                for item in select_component_updates(client=client)
            ],
        }
    )


@require_GET
def browser_catalog(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        if client.desktop_client_product != "dollar":
            raise ValueError("Dollar client required")
    except (ValueError, signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    payload = current_catalog()
    if payload is None:
        return _json_response({"message": "No validated browser catalog is available yet."}, status=503)
    response = _json_response(payload)
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_GET
def desktop_component_download(request: HttpRequest, release_id: int) -> HttpResponse:
    try:
        client = _authenticated_client(request)
        release = DesktopComponentRelease.objects.get(
            pk=release_id,
            status=DesktopComponentRelease.STATUS_PUBLISHED,
            channel=client.release_channel,
        )
        if not release_applies_to_client(release, client):
            raise DesktopComponentRelease.DoesNotExist
        verify_component_signature(release)
        if not release.artifact:
            raise DesktopComponentRelease.DoesNotExist
        release.artifact.open("rb")
    except (
        OSError,
        ValidationError,
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
        DesktopComponentRelease.DoesNotExist,
    ):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    filename = (
        release.original_filename.replace("\\", "/").rsplit("/", 1)[-1]
        or f"dollar-{release.component}-{release.version}.zip"
    )
    response = FileResponse(
        release.artifact,
        as_attachment=True,
        filename=filename,
        content_type="application/octet-stream",
    )
    response["Content-Length"] = str(release.artifact_size)
    response["X-Content-SHA256"] = release.artifact_sha256
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _ensure_dynamic_inventory(
    *,
    client: ClientAccess,
    provider_code: str,
    country_code: str,
    region: str,
    city: str,
    minimum_available: int,
) -> ProxyPoolTarget:
    """Ensure one P2/P3 scope has enough candidates for the current request.

    P2/P3 API proxy generation only builds signed-in proxy usernames; it does
    not make a provider network request. Keeping this path synchronous prevents
    a quality-check request from draining a state/city pool while automatic
    Celery refills are disabled. Existing administrator-defined pool sizes are
    preserved; the level defaults apply only when the target is first created.
    """
    if city:
        target_count, replenish_below = 40, 8
    elif region:
        target_count, replenish_below = 50, 10
    else:
        target_count, replenish_below = 1000, 200
    target, _created = ProxyPoolTarget.objects.get_or_create(
        config_bundle=client.config_bundle,
        provider_code=provider_code,
        country_code=country_code,
        region=region,
        city=city,
        defaults={
            "target_count": target_count,
            "replenish_below": replenish_below,
            "active": True,
        },
    )
    target = (
        ProxyPoolTarget.objects.select_for_update()
        .select_related("config_bundle")
        .get(pk=target.pk)
    )
    if not target.active:
        raise ValueError("Proxy pool target is inactive")

    desired = max(1, int(minimum_available))
    available = target.entries.filter(state="available").count()
    needed = max(0, desired - available)
    if not needed:
        return target
    config = target.config_bundle.get_payload()
    entries: list[ProxyPoolEntry] = []
    for line in _generate(
        provider_code,
        country_code,
        region,
        city,
        needed,
        config,
    ):
        entry = ProxyPoolEntry(
            target=target,
            proxy_fingerprint=proxy_fingerprint(line),
        )
        entry.set_proxy(line)
        entries.append(entry)
    ProxyPoolEntry.objects.bulk_create(entries, batch_size=10)
    return target


@csrf_exempt
@require_POST
def create_proxy_job(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        provider_code = str(body.get("provider") or "").strip().upper()
        if not _provider_is_allowed(client, provider_code):
            raise ValueError("Provider access denied")
        if str(body.get("operation") or "").strip().lower() == "profile-create":
            permissions = _desktop_permissions(client)
            browser_code = str(body.get("browser") or "").strip().upper()
            device_code = str(body.get("device") or "").strip().lower()
            if (
                browser_code not in set(permissions["browsers"])
                or device_code not in set(permissions["devices"])
            ):
                raise ValueError("Browser or device access denied")
        if warrior_proxy_enabled():
            return warrior_proxy_relay(client, "create", request=body)
        raw_country = str(body.get("country") or "").strip()
        region = str(body.get("region") or "").strip()[:120]
        city = str(body.get("city") or "").strip()[:120]
        country_code, region, city = _decode_p3_legacy_location(
            provider_code,
            raw_country,
            region,
            city,
        )
        submitted_count = int(body.get("count") or 1)
        requested_count = submitted_count
        candidate_count = int(
            body.get("candidate_count") or requested_count
        )
        if region.casefold() in {"any", "all", "random"}:
            region = ""
        if city.casefold() in {"any", "all", "random"}:
            city = ""
        if (
            not provider_code
            or not country_code
            or not 1 <= submitted_count <= MAX_PROFILES_PER_REQUEST
            or not requested_count <= candidate_count <= 50
        ):
            raise ValueError("Invalid proxy request")
        if provider_code not in {"P2", "P3"}:
            city = ""
        if provider_code in {"P2", "P3"} and not ProxyCountryFile.objects.filter(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            active=True,
        ).exists():
            raise ValueError("Unsupported provider country")
        # Massive resolves city targeting independently and documents that a
        # city takes precedence over subdivision. Store city pools without a
        # region so the same ready inventory serves both country+city and
        # country+state+city selections.
        if provider_code == "P3" and city:
            region = ""
        if provider_code not in {"P1", "P2", "P3"}:
            region = ""
        elif region and not ProxyRegionCatalog.objects.filter(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            region_code=region,
            active=True,
        ).exists():
            raise ValueError("Unsupported provider region")
        if provider_code == "P2" and city:
            account_key = p2_geo_account_key_from_config(
                client.config_bundle.get_payload()
            )
            if not account_key:
                raise ValueError("P2 geo account is unavailable")
            catalog_query = ProxyCityCatalog.objects.filter(
                provider__code="P2",
                provider__active=True,
                account_key=account_key,
                country_code=country_code,
                city_name=city,
                active=True,
            )
            if region:
                catalog_query = catalog_query.filter(region_code=region)
            city = str(
                catalog_query.order_by("city_name").values_list(
                    "city_name", flat=True
                ).first()
                or ""
            )
            if not city:
                raise ValueError("Unsupported P2 city")
        if provider_code == "P3" and city:
            city = p3_city_name(country_code, city)
            if not city:
                raise ValueError("Unsupported P3 city")
        if provider_code in {"P2", "P3"} and city:
            # Profile creation stays deliberately small, while Tubelight can
            # quality-test a wider city batch before choosing those profiles.
            if requested_count > 10:
                raise ValueError("Exact city requests are limited to 10 profiles")
            candidate_count = min(candidate_count, EXACT_CITY_CANDIDATE_LIMIT)
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    try:
        with transaction.atomic():
            if provider_code in {"P2", "P3"}:
                _ensure_dynamic_inventory(
                    client=client,
                    provider_code=provider_code,
                    country_code=country_code,
                    region=region,
                    city=city,
                    minimum_available=candidate_count,
                )
            job = ProxyGenerationJob.objects.create(
                client=client, provider_code=provider_code, country_code=country_code,
                region=region, city=city, submitted_count=submitted_count,
                requested_count=requested_count,
                candidate_count=candidate_count,
                status="queued",
            )
            reservations = reserve_pool_proxies(
                client=client, job=job, provider_code=provider_code,
                country_code=country_code, region=region, city=city,
            )
            if len(reservations) < candidate_count and not region and not city:
                reservations += reserve_static_proxies(
                    client=client, job=job, provider_code=provider_code,
                    country_code=country_code, region=region, city=city,
                )
            job.ready_count = len(reservations)
            if job.ready_count >= candidate_count:
                job.status = "ready"
            elif job.ready_count:
                job.status = "partial"
            else:
                job.status = (
                    "waiting_generation"
                    if settings.AUTO_GENERATE_PROXY_ON_DEMAND
                    else "failed"
                )
            if (
                job.ready_count < candidate_count
                and not settings.AUTO_GENERATE_PROXY_ON_DEMAND
            ):
                job.error = (
                    f"Only {job.ready_count} proxy/proxies are available for "
                    f"{provider_code} {country_code}. Automatic generation is "
                    "disabled; the administrator has been notified."
                )
                record_proxy_inventory_shortage(
                    client=client,
                    provider_code=provider_code,
                    country_code=country_code,
                    region=region,
                    city=city,
                    available_count=job.ready_count,
                    requested_count=candidate_count,
                )
            job.save(
                update_fields=("ready_count", "status", "error", "updated_at")
            )
            if (
                settings.AUTO_GENERATE_PROXY_ON_DEMAND
                and settings.CELERY_BROKER_URL
                and job.ready_count < candidate_count
            ):
                target = get_or_create_pool_target(
                    client=client, provider_code=provider_code,
                    country_code=country_code, region=region, city=city,
                )
                transaction.on_commit(
                    lambda target_id=target.pk: queue_refill_proxy_pool(target_id)
                )
    except ValueError:
        return _json_response(
            {"allowed": False, "message": "Access denied."}, status=403
        )
    return _json_response({"allowed": True, "job": _job_payload(job)}, status=201)


@require_GET
def proxy_job_detail(request: HttpRequest, job_id: int) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        if warrior_proxy_enabled():
            return warrior_proxy_relay(client, "status", job_id=job_id)
        job = ProxyGenerationJob.objects.get(pk=job_id, client=client)
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist, ProxyGenerationJob.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    return _json_response({"allowed": True, "job": _job_payload(job)})


@csrf_exempt
@require_POST
def proxy_exit_ip_claim(request: HttpRequest) -> JsonResponse:
    """Check or claim a tested proxy exit IP before profile-create.

    ``check`` is a non-mutating optimization before IPQS. ``claim`` is the
    authoritative atomic operation after quality acceptance (or immediately
    after the connectivity probe while IPQS is off). Duplicate claims are a
    normal candidate-selection result, so they return HTTP 200.
    """
    try:
        client = _authenticated_client(request)
    except (
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."}, status=403
        )

    if warrior_proxy_enabled():
        try:
            bridge_body = json.loads(request.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _json_response({"allowed": False, "message": "Invalid exit-IP claim."}, status=400)
        return warrior_proxy_relay(client, "claim", request=bridge_body)

    try:
        body = json.loads(request.body.decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("Invalid payload")
        action = str(body.get("action") or "claim").strip().lower()
        if action not in {"check", "claim"}:
            raise ValueError("Invalid action")
        exit_ip = normalize_exit_ip(body.get("exit_ip"))
        provider_code = str(body.get("provider") or "").strip().upper()
        if not re.fullmatch(r"[A-Z0-9_-]{1,32}", provider_code):
            raise ValueError("Invalid provider")
        if not _provider_is_allowed(client, provider_code):
            raise ValueError("Provider access denied")

        raw_job_id = body.get("job_id")
        raw_reservation_id = body.get("reservation_id")
        job_id = int(raw_job_id) if raw_job_id not in (None, "") else None
        reservation_id = (
            int(raw_reservation_id)
            if raw_reservation_id not in (None, "")
            else None
        )
        if (job_id is not None and job_id < 1) or (
            reservation_id is not None and reservation_id < 1
        ):
            raise ValueError("Invalid reference")
        raw_score = body.get("fraud_score")
        fraud_score = int(raw_score) if raw_score not in (None, "") else None
        if fraud_score is not None and not 0 <= fraud_score <= 100:
            raise ValueError("Invalid fraud score")
    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return _json_response(
            {"allowed": False, "message": "Invalid exit-IP claim."}, status=400
        )

    try:
        job = (
            ProxyGenerationJob.objects.get(pk=job_id, client=client)
            if job_id is not None
            else None
        )
        reservation = (
            ProxyReservation.objects.select_related("job", "pool_entry").get(
                pk=reservation_id,
                client=client,
            )
            if reservation_id is not None
            else None
        )
        if reservation is not None:
            if reservation.provider_code.upper() != provider_code:
                raise ValueError("Provider mismatch")
            if job is None:
                job = reservation.job
            elif reservation.job_id != job.pk:
                raise ValueError("Job mismatch")
        if job is not None and job.provider_code.upper() != provider_code:
            raise ValueError("Provider mismatch")
    except (
        ValueError,
        ProxyGenerationJob.DoesNotExist,
        ProxyReservation.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."}, status=403
        )

    if action == "check":
        checked = check_exit_ip(exit_ip=exit_ip, reservation=reservation)
        row = checked.cooldown
        payload = {
            "allowed": True,
            "action": "check",
            "claimed": False,
            "duplicate": checked.duplicate,
            "idempotent": False,
            "exit_ip": exit_ip,
            "cooldown_seconds": cooldown_seconds(),
            "retry_after_seconds": 0,
        }
        if row is not None:
            now = timezone.now()
            payload.update(
                {
                    "claimed_at": row.claimed_at.isoformat(),
                    "available_after": row.available_after.isoformat(),
                    "retry_after_seconds": max(
                        0,
                        int(
                            (row.available_after - now).total_seconds()
                            + 0.999999
                        ),
                    ),
                }
            )
        if checked.duplicate:
            payload["reason"] = "exit_ip_cooldown"
        return _json_response(payload)

    result = claim_exit_ip(
        client=client,
        provider_code=provider_code,
        exit_ip=exit_ip,
        job=job,
        reservation=reservation,
        fraud_score=fraud_score,
    )
    row = result.cooldown
    now = timezone.now()
    retry_after_seconds = max(
        0,
        int((row.available_after - now).total_seconds() + 0.999999),
    )
    payload = {
        "allowed": True,
        "action": "claim",
        "claimed": result.claimed,
        "duplicate": not result.claimed,
        "idempotent": result.idempotent,
        "exit_ip": str(row.exit_ip),
        "claimed_at": row.claimed_at.isoformat(),
        "available_after": row.available_after.isoformat(),
        "cooldown_seconds": cooldown_seconds(),
        "retry_after_seconds": retry_after_seconds,
    }
    if not result.claimed:
        payload["reason"] = "exit_ip_cooldown"
    return _json_response(payload)


@require_GET
def proxy_cities(
    request: HttpRequest,
    provider_code: str,
    country_code: str,
    region_code: str = "",
) -> JsonResponse:
    """Return live server-managed P2/P3 cities for the authenticated client."""
    try:
        client = _authenticated_client(request)
        if warrior_proxy_enabled():
            return warrior_proxy_relay(
                client,
                "cities",
                provider=str(provider_code or ""),
                country=str(country_code or ""),
                region=str(region_code or ""),
            )
        provider = str(provider_code or "").strip().upper()
        if not _provider_is_allowed(client, provider):
            raise ValueError("Provider access denied")
        country, region, _city = _decode_p3_legacy_location(
            provider,
            country_code,
            region_code,
            "",
        )
        if provider not in {"P2", "P3"} or not country:
            raise ValueError("Unsupported proxy city request")
        if provider == "P2":
            account_key = p2_geo_account_key_from_config(
                client.config_bundle.get_payload()
            )
            if not account_key:
                raise ValueError("P2 geo account is unavailable")
        else:
            account_key = P3_GEO_ACCOUNT_KEY
        if region and not ProxyRegionCatalog.objects.filter(
            provider__code=provider,
            provider__active=True,
            country_code=country,
            region_code=region,
            active=True,
        ).exists():
            raise ValueError("Unsupported provider region")
        city_query = ProxyCityCatalog.objects.filter(
            provider__code=provider,
            provider__active=True,
            account_key=account_key,
            country_code=country,
            active=True,
        )
        if region:
            regional_cities = city_query.filter(region_code=region)
            # P3 publishes its selectable city catalog at country scope while
            # region/state is a separate provider constraint.  Do not empty
            # the City dropdown merely because those city records have no
            # duplicate per-region rows.  P2 remains strict because its city
            # catalog is account- and region-specific.
            if provider == "P3" and not regional_cities.exists():
                pass
            else:
                city_query = regional_cities
        cities = list(
            city_query.order_by("city_name")
            .values_list("city_name", flat=True)
            .distinct()[:25000]
        )
    except (
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."},
            status=403,
        )
    return _json_response({"allowed": True, "cities": cities})


@csrf_exempt
@require_POST
def profile_activity(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        job_id = body.get("job_id")
        reservation_id = body.get("reservation_id")
        status = str(body.get("status") or "").strip()[:32]
        if not status:
            raise ValueError("Missing status")
        job = ProxyGenerationJob.objects.get(pk=job_id, client=client) if job_id else None
        reservation = ProxyReservation.objects.get(pk=reservation_id, client=client) if reservation_id else None
        urls = body.get("start_urls", [])
        if not isinstance(urls, list):
            raise ValueError("Invalid URLs")
        ProfileActivity.objects.create(
            client=client, job=job, reservation=reservation,
            group_id=str(body.get("group_id") or "")[:64],
            profile_name=str(body.get("profile_name") or "")[:160],
            profile_id=str(body.get("profile_id") or "")[:128], status=status,
            start_urls_json=json.dumps(urls)[:10000], detail=str(body.get("detail") or "")[:4000],
        )
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist,
            ProxyGenerationJob.DoesNotExist, ProxyReservation.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    return _json_response({"allowed": True}, status=201)


_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalized_domain(value: Any) -> str:
    raw = str(value or "").strip().casefold().rstrip(".")
    if not raw or len(raw) > 253:
        raise ValueError("Invalid domain")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if any(character in raw for character in "/\\?#@:"):
        raise ValueError("Only a hostname is accepted")
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain") from exc
    labels = domain.split(".")
    if not labels or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain")
    return domain


def _activity_datetime(value: Any) -> Any:
    parsed = parse_datetime(str(value or "").strip())
    if parsed is None:
        raise ValueError("Invalid activity timestamp")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, datetime_timezone.utc)
    return parsed


@csrf_exempt
@require_POST
def profile_domains(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    try:
        body = json.loads(request.body.decode("utf-8"))
        session_id = str(body.get("session_id") or "").strip()
        profile_id = str(body.get("profile_id") or "").strip()[:128]
        if not _SESSION_ID_RE.fullmatch(session_id) or not profile_id:
            raise ValueError("Invalid profile session")
        session_started_at = _activity_datetime(body.get("session_started_at"))
        session_ended_at = _activity_datetime(body.get("session_ended_at"))
        if session_ended_at < session_started_at:
            raise ValueError("Invalid profile session interval")
        raw_domains = body.get("domains")
        if not isinstance(raw_domains, list) or not 1 <= len(raw_domains) <= 2000:
            raise ValueError("Invalid domain batch")
        job_id = body.get("job_id")
        reservation_id = body.get("reservation_id")
        job = (
            ProxyGenerationJob.objects.get(pk=job_id, client=client)
            if job_id else None
        )
        reservation = (
            ProxyReservation.objects.get(pk=reservation_id, client=client)
            if reservation_id else None
        )
        normalized: dict[str, dict[str, Any]] = {}
        for item in raw_domains:
            if not isinstance(item, dict):
                raise ValueError("Invalid domain row")
            domain = _normalized_domain(item.get("domain"))
            first_visited_at = _activity_datetime(item.get("first_visited_at"))
            last_visited_at = _activity_datetime(item.get("last_visited_at"))
            if last_visited_at < first_visited_at:
                raise ValueError("Invalid domain interval")
            visit_count = max(1, min(100000, int(item.get("visit_count") or 1)))
            existing = normalized.get(domain)
            if existing is None:
                normalized[domain] = {
                    "first_visited_at": first_visited_at,
                    "last_visited_at": last_visited_at,
                    "visit_count": visit_count,
                }
            else:
                existing["first_visited_at"] = min(
                    existing["first_visited_at"], first_visited_at
                )
                existing["last_visited_at"] = max(
                    existing["last_visited_at"], last_visited_at
                )
                existing["visit_count"] = min(
                    100000, existing["visit_count"] + visit_count
                )
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            ProxyGenerationJob.DoesNotExist, ProxyReservation.DoesNotExist):
        return _json_response(
            {"allowed": True, "message": "Invalid domain activity payload."},
            status=400,
        )

    group_id = str(body.get("group_id") or "")[:64]
    profile_name = str(body.get("profile_name") or "")[:160]
    browser_id = str(body.get("browser_id") or "")[:64]
    created = 0
    updated = 0
    with transaction.atomic():
        for domain, activity in normalized.items():
            _row, was_created = ProfileDomainActivity.objects.update_or_create(
                client=client,
                profile_id=profile_id,
                session_id=session_id,
                domain=domain,
                defaults={
                    "job": job,
                    "reservation": reservation,
                    "group_id": group_id,
                    "profile_name": profile_name,
                    "browser_id": browser_id,
                    "first_visited_at": activity["first_visited_at"],
                    "last_visited_at": activity["last_visited_at"],
                    "visit_count": activity["visit_count"],
                    "session_started_at": session_started_at,
                    "session_ended_at": session_ended_at,
                },
            )
            if was_created:
                created += 1
            else:
                updated += 1
        if reservation is not None:
            reservation.profile_id = profile_id
            reservation.profile_name = profile_name
            reservation.save(update_fields=("profile_id", "profile_name"))
    return _json_response(
        {
            "allowed": True,
            "accepted": len(normalized),
            "created": created,
            "updated": updated,
        },
        status=201,
    )
