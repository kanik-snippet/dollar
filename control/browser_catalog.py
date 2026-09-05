"""Read-only upstream metadata sync. Never imports accounts, keys or executables."""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from datetime import timedelta
from urllib import error, parse, request

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from .models import BrowserCatalogSnapshot

COMMON_KEYS = frozenset((
    "osData", "winCpuList", "fontList", "winScreen", "countries", "browserType",
    "winRamList", "versionsByMajor", "Intel", "AMD", "NVIDIA", "font",
    "voiceList", "extendedVoices", "macVoiceList", "langInfo",
    "mobileDeviceProfiles", "mobileFonts", "mobileGpuRenderers",
))
OBJECT_KEYS = frozenset(("osData", "versionsByMajor"))
REQUIRED_KEYS = frozenset(("osData", "winCpuList", "fontList", "winScreen"))
UPSTREAM = "https://admin.ysbrowser.com"
MAX_BYTES = 8 * 1024 * 1024
MAX_PAGES = 20
PAGE_SIZE = 100


class CatalogSyncError(Exception):
    """Messages are deliberately static: no response bodies, URLs or credentials."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def validate_tree(value, depth=0):
    if depth > 12:
        raise CatalogSyncError("Catalog nesting exceeds the supported limit.")
    if isinstance(value, dict):
        if len(value) > 10000:
            raise CatalogSyncError("Catalog object exceeds the supported limit.")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128 or key in {"__proto__", "prototype", "constructor"}:
                raise CatalogSyncError("Catalog contains an unsupported object key.")
            validate_tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 25000:
            raise CatalogSyncError("Catalog array exceeds the supported limit.")
        for item in value:
            validate_tree(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192:
            raise CatalogSyncError("Catalog string exceeds the supported limit.")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise CatalogSyncError("Catalog contains an unsupported value.")


def validate_common(data):
    if not isinstance(data, dict):
        raise CatalogSyncError("Common catalog response must be an object.")
    result = {}
    for key in COMMON_KEYS.intersection(data):
        value = data[key]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                raise CatalogSyncError("Common catalog contains invalid JSON.") from None
        if not isinstance(value, dict if key in OBJECT_KEYS else list):
            raise CatalogSyncError("Common catalog has an incompatible field type.")
        validate_tree(value)
        validate_catalog_shape(key, value)
        result[key] = value
    if any(not result.get(key) for key in REQUIRED_KEYS):
        raise CatalogSyncError("Common catalog is missing required non-empty fingerprint fields.")
    try:
        size = len(canonical(result).encode("utf-8"))
    except (ValueError, OverflowError):
        raise CatalogSyncError("Common catalog contains a non-finite value.") from None
    if size > MAX_BYTES:
        raise CatalogSyncError("Common catalog exceeds the supported size.")
    return result


def validate_catalog_shape(key, value):
    def text(value):
        return isinstance(value, str) and bool(value.strip()) and len(value) <= 256

    def positive(value):
        return type(value) in (int, float) and math.isfinite(value) and 0 < value <= 4096

    valid = True
    if key == "osData":
        valid = bool(value.get("Windows")) and all(text(platform) and isinstance(options, list) and all(
            isinstance(row, dict) and text(row.get("label")) and text(row.get("value"))
            for row in options
        ) for platform, options in value.items())
    elif key == "fontList":
        valid = all(isinstance(row, dict) and type(row.get("id")) is int and row["id"] >= 0 and text(row.get("name")) for row in value)
    elif key in {"winCpuList", "winRamList"}:
        capacity = "cores" if key == "winCpuList" else "size"
        valid = all(isinstance(row, dict) and positive(row.get(capacity)) and
                    type(row.get("weight")) in (int, float) and math.isfinite(row["weight"]) and 0 <= row["weight"] <= 100
                    for row in value)
    elif key == "winScreen":
        valid = all(isinstance(row, dict) and text(row.get("label")) and isinstance(row.get("value"), str) and
                    re.fullmatch(r"[1-9][0-9]{1,4}x[1-9][0-9]{1,4}", row["value"]) for row in value)
    elif key == "versionsByMajor":
        valid = all(re.fullmatch(r"[0-9]{2,3}", major) and isinstance(versions, list) and all(
            isinstance(version, str) and re.fullmatch(r"[0-9]{2,3}(?:\.[0-9]{1,6}){3}", version) and version.split(".")[0] == major
            for version in versions
        ) for major, versions in value.items())
    if not valid:
        raise CatalogSyncError("Fingerprint catalog fields have an unsupported schema.")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the original account key to a redirected host.
        raise CatalogSyncError("Upstream redirect refused.")


def upstream_post(path, fields=None, api_key=""):
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if api_key:
        if len(api_key) > 4096 or any(char in api_key for char in "\r\n"):
            raise CatalogSyncError("Invalid server-side YS API key format.")
        headers["X-API-Key"] = api_key
    req = request.Request(UPSTREAM + path, data=parse.urlencode(fields or {}).encode("ascii"), headers=headers, method="POST")
    # Ignore ambient HTTP_PROXY variables. System CA validation remains enabled.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=15) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise CatalogSyncError("Upstream response exceeds the supported size.")
        body = json.loads(raw)
    except CatalogSyncError:
        raise
    except error.HTTPError as exc:
        raise CatalogSyncError(f"YS returned HTTP {int(exc.code)}.") from None
    except (OSError, ValueError, error.URLError, RecursionError):
        raise CatalogSyncError("YS request failed: network, TLS, timeout or invalid JSON.") from None
    if not isinstance(body, dict) or type(body.get("code")) is not int or body["code"] != 0:
        raise CatalogSyncError("YS rejected the catalog request or changed its response format.")
    return body.get("data")


def validate_browser_row(row):
    if not isinstance(row, dict) or not re.fullmatch(r"[0-9]{2,3}(?:\.[0-9]{1,6}){0,3}", str(row.get("version", ""))):
        raise CatalogSyncError("Browser version metadata has an unsupported schema.")
    # Metadata is discovery only. Host OS does NOT classify Android-emulating binaries.
    out = {"version": str(row["version"]), "runtime_target": "unverified", "installable": False}
    for key in ("versionName", "releaseDate", "osVersion", "browserType"):
        value = row.get(key)
        if value is not None:
            if type(value) not in (str, int) or len(str(value)) > 160 or re.search(r"[\x00-\x1f]|://", str(value)):
                raise CatalogSyncError("Browser version metadata contains an invalid field.")
            out[key] = value
    # No downloadUrl, arbitrary release HTML, script, token or account data reaches clients.
    return out


def fetch_browser_versions(api_key):
    if not api_key:
        raise CatalogSyncError("YS_UPSTREAM_API_KEY is required for browser package metadata sync.")
    result, pages_seen, expected_total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        data = upstream_post("/api/aegisVersion/aegisCheck", {"pageNum": page, "pageSize": PAGE_SIZE}, api_key)
        if isinstance(data, dict) and isinstance(data.get("rows"), list):
            rows = data["rows"]
            total = data.get("total")
            if total is not None:
                if isinstance(total, bool) or not str(total).isdigit() or int(total) > MAX_PAGES * PAGE_SIZE:
                    raise CatalogSyncError("Browser version total exceeds the supported limit.")
                if expected_total is not None and int(total) != expected_total:
                    raise CatalogSyncError("Browser version catalog changed during pagination; retry later.")
                expected_total = int(total)
        elif isinstance(data, list):
            rows = data
        else:
            raise CatalogSyncError("Browser version response has an unsupported envelope.")
        marker = digest(rows)
        if len(rows) > PAGE_SIZE or len(result) + len(rows) > PAGE_SIZE * MAX_PAGES:
            raise CatalogSyncError("YS browser page exceeds the supported size.")
        if rows and marker in pages_seen:
            raise CatalogSyncError("YS repeated a browser catalog page; last valid snapshot retained.")
        pages_seen.add(marker)
        result.extend(validate_browser_row(row) for row in rows)
        if expected_total is not None:
            if len(result) > expected_total or (not rows and len(result) < expected_total):
                raise CatalogSyncError("YS returned incomplete browser metadata.")
            done = len(result) == expected_total
        else:
            done = len(rows) < PAGE_SIZE
        if done:
            if not result:
                raise CatalogSyncError("YS returned an empty browser catalog; last valid snapshot retained.")
            return sorted(result, key=canonical)
    raise CatalogSyncError("YS browser catalog exceeded the pagination limit.")


def sync_resource(name, fetch):
    now, lease = timezone.now(), uuid.uuid4().hex
    row, _ = BrowserCatalogSnapshot.objects.get_or_create(name=name)
    acquired = BrowserCatalogSnapshot.objects.filter(pk=row.pk).filter(
        Q(lease_until__isnull=True) | Q(lease_until__lt=now)
    ).update(lease_token=lease, lease_until=now + timedelta(minutes=15), last_attempt_at=now)
    if not acquired:
        return {"resource": name, "status": "busy"}
    owned = BrowserCatalogSnapshot.objects.filter(pk=row.pk, lease_token=lease)
    try:
        row = owned.get()
        data = fetch()
        if name == "common" and row.payload:
            # A partial upstream update must not erase previously known safe catalogs.
            data = {**{k: v for k, v in row.payload.items() if k in COMMON_KEYS}, **data}
        if name == "common":
            data = validate_common(data)
        revision = digest(data)
        updates = dict(payload=data, revision=revision, last_success_at=timezone.now(), last_error="", lease_token="", lease_until=None)
        if revision != row.revision:
            updates["data_updated_at"] = timezone.now()
        if not owned.update(**updates):
            return {"resource": name, "status": "lease_lost"}
        return {"resource": name, "status": "updated" if revision != row.revision else "unchanged", "revision": revision, "count": len(data)}
    except Exception as exc:
        message = str(exc) if isinstance(exc, CatalogSyncError) else "Catalog sync failed internally; last valid snapshot retained."
        owned.update(last_error=message, lease_token="", lease_until=None)
        return {"resource": name, "status": "failed", "error": message}


def sync_catalogs(*, force=False):
    if not force and not settings.YS_CATALOG_SYNC_ENABLED:
        return [{"status": "disabled"}]
    results = [sync_resource("common", lambda: validate_common(upstream_post("/api/common/getWebConfigValue")))]
    results.append(sync_resource("browser_versions", lambda: fetch_browser_versions(settings.YS_UPSTREAM_API_KEY)))
    return results


def current_catalog(*, descriptor=False):
    query = BrowserCatalogSnapshot.objects.filter(name__in=("common", "browser_versions")).exclude(revision="")
    if descriptor:
        query = query.only("name", "revision", "data_updated_at")
    rows = {row.name: row for row in query}
    common = rows.get("common")
    if common is None:
        return None
    versions = rows.get("browser_versions")
    revision = digest({name: row.revision for name, row in sorted(rows.items()) if name in {"common", "browser_versions"}})
    updated = max((row.data_updated_at for row in rows.values() if row.data_updated_at), default=timezone.now())
    result = {"schema_version": 1, "revision": revision, "updated_at": updated.isoformat()}
    if descriptor:
        result["download_path"] = "/api/v1/browser-catalog/"
    else:
        result.update(catalogs=common.payload, browser_versions=versions.payload if versions else [])
    return result
