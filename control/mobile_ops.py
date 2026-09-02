from __future__ import annotations

import ipaddress
import json
from datetime import timedelta
from typing import Any

from django.contrib.admin.views.decorators import staff_member_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .geo_catalog import country_rows
from .models import (
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    ProxyPoolTarget,
    YSBridgeAgent,
    YSBridgeCommand,
)
from .panel_views import panel_json
from .tasks import provider_is_configured, refill_proxy_pool


SUPPORTED_PROVIDERS = ("P1", "P2", "P3", "P4")
BRIDGE_RESULT_LIMIT = 128 * 1024


def _json_body(request: HttpRequest) -> dict[str, Any]:
    if len(request.body) > BRIDGE_RESULT_LIMIT:
        raise ValueError("Request body is too large.")
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid JSON body.") from exc
    if not isinstance(body, dict):
        raise ValueError("JSON body must be an object.")
    return body


def _active_offices() -> list[str]:
    return list(
        ClientAccess.objects.filter(active=True)
        .exclude(office_name="")
        .order_by("office_name")
        .values_list("office_name", flat=True)
        .distinct()
    )


def _active_agent() -> YSBridgeAgent | None:
    return YSBridgeAgent.objects.filter(active=True).order_by("name", "pk").first()


def _agent_row(agent: YSBridgeAgent | None) -> dict[str, Any] | None:
    if agent is None:
        return None
    online = bool(
        agent.last_seen_at
        and agent.last_seen_at >= timezone.now() - timedelta(seconds=30)
    )
    return {
        "id": agent.pk,
        "name": agent.name,
        "online": online,
        "last_seen": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "version": agent.version,
    }


def _command_row(command: YSBridgeCommand) -> dict[str, Any]:
    result = command.result if isinstance(command.result, dict) else {}
    return {
        "id": str(command.pk),
        "action": command.action,
        "action_label": command.get_action_display(),
        "office": command.office_name or "All offices",
        "status": command.status,
        "error": command.error,
        "result": result,
        "requested_at": command.requested_at.isoformat(),
        "completed_at": command.completed_at.isoformat() if command.completed_at else None,
    }


def _require_superuser(request: HttpRequest) -> JsonResponse | None:
    if request.user.is_superuser:
        return None
    return panel_json(
        {"ok": False, "message": "Super-admin access is required."}, status=403
    )


def _add_office_ipv4(office: str, raw_ip: str) -> dict[str, Any]:
    office = office.strip()
    if not office:
        raise ValueError("Choose an office.")
    try:
        parsed = ipaddress.ip_address(raw_ip.strip())
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported.")
    normalized_ip = str(parsed)
    clients = list(
        ClientAccess.objects.filter(office_name__iexact=office, active=True)
        .only("id", "ipv4")
        .order_by("pk")
    )
    if not clients:
        raise LookupError("No active devices exist in that office.")

    created = reactivated = primary_skipped = existing_skipped = 0
    with transaction.atomic():
        for client in clients:
            if normalized_ip == str(client.ipv4):
                primary_skipped += 1
                continue
            entry, was_created = ClientAccessIP.objects.get_or_create(
                client=client,
                ipv4=normalized_ip,
                defaults={"active": True},
            )
            if was_created:
                created += 1
            elif not entry.active:
                entry.active = True
                entry.save(update_fields=("active",))
                reactivated += 1
            else:
                existing_skipped += 1
    return {
        "office": office,
        "ipv4": normalized_ip,
        "devices": len(clients),
        "created": created,
        "reactivated": reactivated,
        "primary_ip_skipped": primary_skipped,
        "existing_additional_skipped": existing_skipped,
    }


def _generate_office_proxies(body: dict[str, Any]) -> dict[str, Any]:
    office = str(body.get("office") or "").strip()
    provider = str(body.get("provider") or "P1").strip().upper()
    country = str(body.get("country") or "").strip().upper()
    try:
        target_count = int(body.get("target_count") or 1000)
    except (TypeError, ValueError) as exc:
        raise ValueError("Target stock must be a number.") from exc
    if not office:
        raise ValueError("Choose an office.")
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError("Choose P1, P2, P3 or P4.")
    valid_countries = {code for code, _name in country_rows()}
    if country not in valid_countries:
        raise ValueError("Enter a valid two-letter country code.")
    if not 1 <= target_count <= 5000:
        raise ValueError("Target stock must be between 1 and 5000.")

    bundle_ids = list(
        ClientAccess.objects.filter(
            office_name__iexact=office,
            active=True,
            config_bundle__active=True,
        )
        .order_by()
        .values_list("config_bundle_id", flat=True)
        .distinct()
    )
    bundles = list(ConfigBundle.objects.filter(pk__in=bundle_ids, active=True))
    if not bundles:
        raise LookupError(f"No active configuration bundles are assigned to {office}.")

    threshold = min(200, max(1, target_count // 5))
    generated = ready = created = already_running = 0
    missing_credentials: list[str] = []
    failures: list[dict[str, str]] = []
    for bundle in bundles:
        if not provider_is_configured(provider, bundle.get_payload()):
            missing_credentials.append(bundle.name)
            continue
        target, was_created = ProxyPoolTarget.objects.get_or_create(
            config_bundle=bundle,
            provider_code=provider,
            country_code=country,
            region="",
            city="",
            defaults={
                "target_count": target_count,
                "replenish_below": threshold,
                "active": True,
            },
        )
        created += int(was_created)
        updates: list[str] = []
        for field, value in (
            ("target_count", target_count),
            ("replenish_below", threshold),
            ("active", True),
        ):
            if getattr(target, field) != value:
                setattr(target, field, value)
                updates.append(field)
        if updates:
            target.save(update_fields=(*updates, "updated_at"))
        available = target.entries.filter(state="available").count()
        if available >= target_count:
            ready += 1
            continue
        recent_claim = (
            target.refill_pending
            and target.refill_requested_at
            and target.refill_requested_at >= timezone.now() - timedelta(minutes=15)
        )
        if recent_claim:
            already_running += 1
            continue
        ProxyPoolTarget.objects.filter(pk=target.pk).update(
            refill_pending=True,
            refill_requested_at=timezone.now(),
        )
        try:
            generated += int(refill_proxy_pool.run(target.pk) or 0)
        except Exception as exc:  # Keep the remaining office bundles actionable.
            failures.append(
                {"bundle": bundle.name, "error": f"{type(exc).__name__}: {exc}"[:300]}
            )

    return {
        "office": office,
        "provider": provider,
        "country": country,
        "target_count": target_count,
        "bundles_found": len(bundles),
        "targets_created": created,
        "proxies_generated": generated,
        "already_ready": ready,
        "already_running": already_running,
        "missing_credentials": missing_credentials,
        "failures": failures,
    }


def _group_ids_for_office(office: str) -> list[str]:
    clients = ClientAccess.objects.filter(active=True, config_bundle__active=True)
    if office != "__all__":
        clients = clients.filter(office_name__iexact=office)
    return sorted(
        {
            str(value).strip()
            for value in clients.values_list(
                "config_bundle__browser_group_id", flat=True
            )
            if str(value or "").strip()
        },
        key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value),
    )


@staff_member_required(login_url="admin:login")
@require_GET
def mobile_ops_page(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "control/mobile_ops.html",
        {
            "api_url": reverse("control:mobile-ops-api"),
            "panel_url": reverse("control:panel"),
            "admin_url": reverse("admin:index"),
        },
    )


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def mobile_ops_api(request: HttpRequest) -> JsonResponse:
    denied = _require_superuser(request)
    if denied:
        return denied
    if request.method == "GET":
        agent = _active_agent()
        commands = YSBridgeCommand.objects.select_related("agent").all()[:20]
        return panel_json(
            {
                "ok": True,
                "offices": _active_offices(),
                "providers": list(SUPPORTED_PROVIDERS),
                "countries": [
                    {"code": code, "name": name} for code, name in country_rows()
                ],
                "agent": _agent_row(agent),
                "commands": [_command_row(command) for command in commands],
            }
        )

    try:
        body = _json_body(request)
    except ValueError as exc:
        return panel_json({"ok": False, "message": str(exc)}, status=400)
    action = str(body.get("action") or "").strip().lower()
    try:
        if action == "generate_proxies":
            result = _generate_office_proxies(body)
            return panel_json(
                {
                    "ok": not result["failures"],
                    "message": (
                        f"{result['provider']} {result['country']} completed for "
                        f"{result['office']}: {result['proxies_generated']} proxies generated."
                    ),
                    "result": result,
                },
                status=200 if not result["failures"] else 207,
            )
        if action == "add_office_ipv4":
            result = _add_office_ipv4(
                str(body.get("office") or ""), str(body.get("ipv4") or "")
            )
            return panel_json(
                {
                    "ok": True,
                    "message": f"{result['ipv4']} added to {result['office']} devices.",
                    "result": result,
                }
            )
        if action == "queue_ys_delete":
            office = str(body.get("office") or "").strip()
            confirmation = str(body.get("confirmation") or "").strip().upper()
            if not office:
                raise ValueError("Choose an office or All offices.")
            if confirmation != "DELETE":
                raise ValueError("Type DELETE to confirm environment deletion.")
            group_ids = _group_ids_for_office(office)
            if not group_ids:
                raise LookupError("No active YS browser group IDs were found for that office.")
            agent = _active_agent()
            if agent is None:
                raise LookupError("No active YS bridge agent is configured.")
            command = YSBridgeCommand.objects.create(
                agent=agent,
                action=YSBridgeCommand.ACTION_DELETE_ENVIRONMENTS,
                office_name="" if office == "__all__" else office,
                payload={"group_ids": group_ids, "delete_local_cache": True},
                requested_by=request.user,
            )
            return panel_json(
                {
                    "ok": True,
                    "message": f"YS deletion queued for {office if office != '__all__' else 'all offices'} ({len(group_ids)} groups).",
                    "command": _command_row(command),
                }
            )
        if action == "queue_ys_whitelist":
            mode = str(body.get("mode") or "add").strip().lower()
            raw_ip = str(body.get("ipv4") or "").strip()
            try:
                parsed = ipaddress.ip_address(raw_ip)
            except ValueError as exc:
                raise ValueError("Enter a valid public IPv4 address.") from exc
            if not isinstance(parsed, ipaddress.IPv4Address):
                raise ValueError("YSBrowser whitelist supports IPv4 only.")
            if mode not in {"add", "remove"}:
                raise ValueError("Choose add or remove.")
            agent = _active_agent()
            if agent is None:
                raise LookupError("No active YS bridge agent is configured.")
            command = YSBridgeCommand.objects.create(
                agent=agent,
                action=(
                    YSBridgeCommand.ACTION_WHITELIST_ADD
                    if mode == "add"
                    else YSBridgeCommand.ACTION_WHITELIST_REMOVE
                ),
                payload={"ipv4": str(parsed)},
                requested_by=request.user,
            )
            return panel_json(
                {
                    "ok": True,
                    "message": f"YSBrowser whitelist {mode} queued for {parsed}.",
                    "command": _command_row(command),
                }
            )
        if action == "retry_command":
            command = YSBridgeCommand.objects.get(pk=body.get("command_id"))
            if command.status not in {
                YSBridgeCommand.STATUS_FAILED,
                YSBridgeCommand.STATUS_CANCELLED,
            }:
                raise ValueError("Only failed or cancelled commands can be retried.")
            command.status = YSBridgeCommand.STATUS_QUEUED
            command.error = ""
            command.result = {}
            command.claimed_at = None
            command.completed_at = None
            command.requested_by = request.user
            command.save(
                update_fields=(
                    "status",
                    "error",
                    "result",
                    "claimed_at",
                    "completed_at",
                    "requested_by",
                )
            )
            return panel_json(
                {"ok": True, "message": "Command queued again.", "command": _command_row(command)}
            )
        raise ValueError("Unknown mobile operation.")
    except (YSBridgeCommand.DoesNotExist, ValidationError):
        return panel_json({"ok": False, "message": "Command was not found."}, status=404)
    except LookupError as exc:
        return panel_json({"ok": False, "message": str(exc)}, status=404)
    except ValueError as exc:
        return panel_json({"ok": False, "message": str(exc)}, status=400)


def _bridge_agent(request: HttpRequest) -> YSBridgeAgent | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    if not token:
        return None
    token_hash = YSBridgeAgent.hash_token(token)
    return YSBridgeAgent.objects.filter(token_hash=token_hash, active=True).first()


def _request_ip(request: HttpRequest) -> str | None:
    raw = str(request.META.get("REMOTE_ADDR") or "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def _bridge_unauthorized() -> JsonResponse:
    response = JsonResponse({"ok": False, "message": "Invalid bridge token."}, status=401)
    response["Cache-Control"] = "no-store"
    response["WWW-Authenticate"] = "Bearer"
    return response


@csrf_exempt
@require_POST
def bridge_poll(request: HttpRequest) -> JsonResponse:
    agent = _bridge_agent(request)
    if agent is None:
        return _bridge_unauthorized()
    now = timezone.now()
    agent.last_seen_at = now
    agent.last_ip = _request_ip(request)
    agent.version = str(request.headers.get("X-Bridge-Version") or "")[:40]
    agent.save(update_fields=("last_seen_at", "last_ip", "version", "updated_at"))
    with transaction.atomic():
        YSBridgeCommand.objects.filter(
            agent=agent,
            status=YSBridgeCommand.STATUS_RUNNING,
            claimed_at__lt=now - timedelta(minutes=15),
        ).update(
            status=YSBridgeCommand.STATUS_QUEUED,
            claimed_at=None,
            error="",
        )
        command = (
            YSBridgeCommand.objects.select_for_update()
            .filter(agent=agent, status=YSBridgeCommand.STATUS_QUEUED)
            .order_by("requested_at")
            .first()
        )
        if command is not None:
            command.status = YSBridgeCommand.STATUS_RUNNING
            command.claimed_at = now
            command.error = ""
            command.save(update_fields=("status", "claimed_at", "error"))
    payload: dict[str, Any] = {"ok": True, "command": None}
    if command is not None:
        payload["command"] = {
            "id": str(command.pk),
            "action": command.action,
            "office": command.office_name,
            "payload": command.payload,
        }
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store"
    return response


@csrf_exempt
@require_POST
def bridge_complete(request: HttpRequest, command_id) -> JsonResponse:
    agent = _bridge_agent(request)
    if agent is None:
        return _bridge_unauthorized()
    try:
        body = _json_body(request)
    except ValueError as exc:
        return JsonResponse({"ok": False, "message": str(exc)}, status=400)
    try:
        with transaction.atomic():
            command = YSBridgeCommand.objects.select_for_update().get(
                pk=command_id, agent=agent
            )
            if command.status != YSBridgeCommand.STATUS_RUNNING:
                return JsonResponse(
                    {"ok": False, "message": "Command is not running."}, status=409
                )
            succeeded = bool(body.get("success"))
            result = body.get("result")
            command.status = (
                YSBridgeCommand.STATUS_SUCCEEDED
                if succeeded
                else YSBridgeCommand.STATUS_FAILED
            )
            command.result = result if isinstance(result, dict) else {}
            command.error = "" if succeeded else str(body.get("error") or "Unknown bridge error.")[:2000]
            command.completed_at = timezone.now()
            command.save(update_fields=("status", "result", "error", "completed_at"))
    except YSBridgeCommand.DoesNotExist:
        return JsonResponse({"ok": False, "message": "Command was not found."}, status=404)
    response = JsonResponse({"ok": True})
    response["Cache-Control"] = "no-store"
    return response
