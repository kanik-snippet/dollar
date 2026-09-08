"""Dollar panel access to Warrior's authoritative, shared cooldown policy."""
from __future__ import annotations

import json

from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpRequest, JsonResponse
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_http_methods

from .panel_views import panel_json
from .warrior_proxy_bridge import cooldown_policy


SHARED_SCOPE = "Shared globally by OPTIX and Dollar; Warrior is the authoritative policy server."


def _policy_payload(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Invalid policy")
    if (
        type(value.get("enabled")) is not bool
        or type(value.get("cooldown_hours")) is not int
        or value["cooldown_hours"] != 25
        or type(value.get("revision")) is not int
        or value["revision"] < 0
    ):
        raise ValueError("Invalid policy")
    updated_at = value.get("updated_at")
    if updated_at is not None and (
        not isinstance(updated_at, str) or len(updated_at) > 64
        or parse_datetime(updated_at) is None
    ):
        raise ValueError("Invalid policy timestamp")
    return {key: value.get(key) for key in ("enabled", "cooldown_hours", "updated_at", "revision")}


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_proxy_cooldown_api(request: HttpRequest) -> JsonResponse:
    can_change = bool(request.user.is_superuser)
    values = {"actor": "dollar:" + request.user.get_username()[:150]}
    operation = "get"
    if request.method == "POST":
        if not can_change:
            return panel_json({"ok": False, "message": "Super-admin access is required."}, status=403)
        try:
            body = json.loads(request.body.decode("utf-8"))
            if (
                not isinstance(body, dict)
                or set(body) != {"enabled", "expected_revision"}
                or type(body.get("enabled")) is not bool
                or type(body.get("expected_revision")) is not int
                or body["expected_revision"] < 0
            ):
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            return panel_json({"ok": False, "message": "Supply an enabled boolean and a nonnegative expected_revision integer."}, status=400)
        operation = "set"
        values.update(enabled=body["enabled"], expected_revision=body["expected_revision"])
    # No local cache or success fallback: a write is successful only after the
    # authoritative server confirms the resulting policy and revision.
    response = cooldown_policy(operation, **values)
    if response.status_code == 409:
        return panel_json({"ok": False, "message": "Cooldown policy changed. Refresh and retry."}, status=409)
    if response.status_code != 200:
        return panel_json({"ok": False, "message": "Warrior did not confirm the cooldown policy. Refresh before retrying; no local fallback was applied."}, status=503)
    try:
        payload = json.loads(response.content.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ValueError
        policy = _policy_payload(payload.get("policy"))
    except (UnicodeDecodeError, ValueError):
        return panel_json({"ok": False, "message": "Warrior returned an invalid cooldown policy. Refresh to verify its current state."}, status=503)
    return panel_json({"ok": True, "policy": policy, "can_change": can_change, "scope": SHARED_SCOPE})
