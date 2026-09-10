"""Authenticated OPTIX-to-Warrior proxy relay client."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.http import JsonResponse


def enabled() -> bool:
    return bool(
        str(getattr(settings, "WARRIOR_PROXY_BRIDGE_URL", "") or "").strip()
        and len(str(getattr(settings, "WARRIOR_PROXY_BRIDGE_SECRET", "") or "")) >= 32
    )


def _identity(client) -> dict[str, str]:
    # Dollar owns and authenticates its device IDs.  Warrior owns the proxy
    # inventory and maps that independently-managed client to the existing
    # office/system bundle.  Forwarding Dollar's device ID made every freshly
    # installed PC require a duplicate Warrior ClientAccess row with the exact
    # same ID, even when the office and system assignment was already valid.
    return {
        "office_name": str(client.office_name),
        "system_number": str(client.system_number),
        "device_id": "",
    }


def _relay_payload(payload: dict) -> JsonResponse:
    if not enabled():
        return JsonResponse({"allowed": False, "message": "OPTIX proxy service is not configured."}, status=503)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    secret = str(settings.WARRIOR_PROXY_BRIDGE_SECRET).encode("utf-8")
    signature = hmac.new(secret, timestamp.encode("ascii") + b"\n" + raw, hashlib.sha256).hexdigest()
    try:
        request = Request(
            str(settings.WARRIOR_PROXY_BRIDGE_URL),
            data=raw,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-OPTIX-Timestamp": timestamp,
                "X-OPTIX-Signature": signature,
            },
        )
        with urlopen(request, timeout=max(5, int(settings.WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS))) as response:
            body = response.read()
            status = response.status
    except HTTPError as error:
        body = error.read()
        status = error.code
    except (URLError, TimeoutError, OSError, ValueError):
        return JsonResponse({"allowed": False, "message": "OPTIX proxy service is unavailable."}, status=503)
    try:
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Expected an object response")
    except (UnicodeDecodeError, ValueError):
        data = {"allowed": False, "message": "OPTIX proxy service returned an invalid response."}
        status = 502
    return JsonResponse(data, status=status)


def relay(client, action: str, **values) -> JsonResponse:
    if action == "cooldown-policy":
        return JsonResponse({"allowed": False, "message": "Administrative policy access is not a desktop action."}, status=403)
    return _relay_payload({"action": action, "client": _identity(client), **values})


def cooldown_policy(operation: str, *, enabled=None, expected_revision=None, actor: str = "") -> JsonResponse:
    """Relay panel policy access without fabricating a desktop ClientAccess."""
    values = {"operation": operation, "actor": actor}
    if operation == "set":
        values.update(enabled=enabled, expected_revision=expected_revision)
    return _relay_payload({"action": "cooldown-policy", "request": values})
