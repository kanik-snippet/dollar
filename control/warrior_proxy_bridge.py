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
    return {
        "office_name": str(client.office_name),
        "system_number": str(client.system_number),
        "device_id": str(client.device_id or ""),
    }


def relay(client, action: str, **values) -> JsonResponse:
    if not enabled():
        return JsonResponse({"allowed": False, "message": "OPTIX proxy service is not configured."}, status=503)
    payload = {"action": action, "client": _identity(client), **values}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    secret = str(settings.WARRIOR_PROXY_BRIDGE_SECRET).encode("utf-8")
    signature = hmac.new(secret, timestamp.encode("ascii") + b"\n" + raw, hashlib.sha256).hexdigest()
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
    try:
        with urlopen(request, timeout=max(5, int(settings.WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS))) as response:
            body = response.read()
            status = response.status
    except HTTPError as error:
        body = error.read()
        status = error.code
    except (URLError, TimeoutError, OSError):
        return JsonResponse({"allowed": False, "message": "OPTIX proxy service is unavailable."}, status=503)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = {"allowed": False, "message": "OPTIX proxy service returned an invalid response."}
        status = 502
    return JsonResponse(data, status=status)
