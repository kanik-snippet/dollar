from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from typing import Any

from django.contrib.admin.views.decorators import staff_member_required
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from .geo_catalog import country_rows
from .models import (
    BootstrapAudit,
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    DEFAULT_DESKTOP_BROWSER_CODES,
    DEFAULT_DESKTOP_DEVICE_CODES,
    DEFAULT_DESKTOP_PROVIDER_CODES,
    DesktopOfficeAccessPolicy,
    Provider,
    ProxyCityCatalog,
    ProxyCountryFile,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyRegionCatalog,
)
from .panel_views import iso, panel_json
from .tasks import provider_is_configured, queue_refill_proxy_pool


HIDDEN_OFFICES = {"personal"}
ACCESS_NOTIFICATION_REASONS = {
    "not-whitelisted",
    "route-denied",
    "ip-mismatch",
    "inactive",
}


def _body(request: HttpRequest) -> dict[str, Any]:
    try:
        value = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid JSON body.") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object.")
    return value


def _visible_offices() -> list[str]:
    rows = (
        ClientAccess.objects.exclude(office_name="")
        .values_list("office_name", flat=True)
        .distinct()
        .order_by("office_name")
    )
    return [name for name in rows if str(name).strip().casefold() not in HIDDEN_OFFICES]


def _selected_office(raw: Any, offices: list[str]) -> str:
    requested = str(raw or "").strip()
    for office in offices:
        if office.casefold() == requested.casefold():
            return office
    return offices[0] if offices else ""


def _ipv4(raw: Any) -> str:
    try:
        parsed = ipaddress.ip_address(str(raw or "").strip())
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported.")
    return str(parsed)


def _client_for_audit(audit: BootstrapAudit) -> ClientAccess | None:
    if audit.client_id:
        return audit.client
    device_id = str(audit.device_id or "").strip()
    if not device_id:
        return None
    # Do not create or merge records here.  If duplicate historical records
    # exist, consistently target the active/oldest one until an admin cleans
    # those rows manually.
    return (
        ClientAccess.objects.select_related("config_bundle")
        .filter(device_id=device_id)
        .order_by("-active", "pk")
        .first()
    )


def _add_client_ip(client: ClientAccess, ip_value: str) -> str:
    if str(client.ipv4) == ip_value:
        return "primary"
    entry, created = ClientAccessIP.objects.get_or_create(
        client=client,
        ipv4=ip_value,
        defaults={"active": True},
    )
    if not created and not entry.active:
        entry.active = True
        entry.save(update_fields=("active",))
        return "reactivated"
    return "created" if created else "existing"


def _client_row(client: ClientAccess) -> dict[str, Any]:
    additional = [str(row.ipv4) for row in getattr(client, "panel_allowed_ips", [])]
    return {
        "id": client.pk,
        "office": client.office_name,
        "system_number": client.system_number,
        "name": client.name,
        "bundle": client.config_bundle.name,
        "device_id": client.device_id,
        "primary_ip": str(client.ipv4),
        "additional_ips": additional,
        "active": client.active,
        "last_seen": iso(client.last_seen_at),
    }


def _audit_row(
    audit: BootstrapAudit,
    *,
    client_override: ClientAccess | None = None,
    identity_resolved: bool = False,
) -> dict[str, Any]:
    client = client_override if identity_resolved else _client_for_audit(audit)
    return {
        "id": audit.pk,
        "office": client.office_name if client else "Unassigned",
        "system_number": client.system_number if client else "—",
        "client_id": client.pk if client else None,
        "device_id": audit.device_id,
        "observed_ip": str(audit.observed_ip or ""),
        "reported_ip": str(audit.reported_ip or ""),
        "reason": audit.reason,
        "app_version": audit.app_version,
        "created_at": iso(audit.created_at),
        "read": audit.read_at is not None,
        "review_status": audit.review_status,
        "can_approve": client is not None,
    }


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_access_api(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        try:
            body = _body(request)
            action = str(body.get("action") or "").strip().lower()
            if action == "mark_read":
                audit = get_object_or_404(BootstrapAudit, pk=body.get("audit_id"))
                if audit.read_at is None:
                    audit.read_at = timezone.now()
                    audit.save(update_fields=("read_at",))
                return panel_json({"ok": True})

            if action in {"approve_request", "reject_request"}:
                audit = get_object_or_404(
                    BootstrapAudit.objects.select_related("client"),
                    pk=body.get("audit_id"),
                    allowed=False,
                )
                client = _client_for_audit(audit)
                if action == "approve_request":
                    if client is None:
                        raise ValueError(
                            "No existing device matches this Device ID. Create its access record first."
                        )
                    evidence = [str(value) for value in (audit.reported_ip, audit.observed_ip) if value]
                    ip_value = _ipv4(body.get("ipv4") or (evidence[0] if evidence else ""))
                    if ip_value not in evidence:
                        raise ValueError("Approval IP must come from the selected access request.")
                    scope = str(body.get("scope") or "device").strip().lower()
                    targets = [client]
                    if scope == "office":
                        targets = list(
                            ClientAccess.objects.filter(
                                office_name__iexact=client.office_name,
                                active=True,
                            ).order_by("pk")
                        )
                    elif scope != "device":
                        raise ValueError("Choose this PC or every PC in the office.")
                    with transaction.atomic():
                        for target in targets:
                            _add_client_ip(target, ip_value)
                        audit.client = client
                        audit.read_at = timezone.now()
                        audit.review_status = BootstrapAudit.REVIEW_APPROVED
                        audit.reviewed_at = timezone.now()
                        audit.reviewed_by = request.user
                        audit.save(
                            update_fields=(
                                "client", "read_at", "review_status",
                                "reviewed_at", "reviewed_by",
                            )
                        )
                    return panel_json({
                        "ok": True,
                        "message": (
                            f"{ip_value} added to {len(targets)} PC(s) in {client.office_name}."
                        ),
                    })

                audit.read_at = timezone.now()
                audit.review_status = BootstrapAudit.REVIEW_REJECTED
                audit.reviewed_at = timezone.now()
                audit.reviewed_by = request.user
                audit.save(
                    update_fields=("read_at", "review_status", "reviewed_at", "reviewed_by")
                )
                return panel_json({"ok": True, "message": "Access request rejected and retained in history."})

            if action == "add_device_ip":
                client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
                ip_value = _ipv4(body.get("ipv4"))
                _add_client_ip(client, ip_value)
                return panel_json({"ok": True, "message": f"{ip_value} added to {client.name}."})

            if action == "add_office_ip":
                offices = _visible_offices()
                office = _selected_office(body.get("office"), offices)
                if not office:
                    raise ValueError("Choose an office.")
                ip_value = _ipv4(body.get("ipv4"))
                targets = list(ClientAccess.objects.filter(office_name__iexact=office, active=True))
                if not targets:
                    raise ValueError("No active PCs exist in this office.")
                with transaction.atomic():
                    for target in targets:
                        _add_client_ip(target, ip_value)
                return panel_json({"ok": True, "message": f"{ip_value} added to {len(targets)} PC(s) in {office}."})

            if action == "set_access":
                client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
                client.active = bool(body.get("active"))
                client.save(update_fields=("active", "updated_at"))
                return panel_json({"ok": True, "message": f"{client.name} access updated."})
            raise ValueError("Unknown Access action.")
        except ValueError as exc:
            return panel_json({"ok": False, "message": str(exc)}, status=400)

    offices = _visible_offices()
    office = _selected_office(request.GET.get("office"), offices)
    clients = ClientAccess.objects.select_related("config_bundle").prefetch_related(
        Prefetch(
            "allowed_ips",
            queryset=ClientAccessIP.objects.filter(active=True).order_by("ipv4"),
            to_attr="panel_allowed_ips",
        )
    )
    if office:
        clients = clients.filter(office_name__iexact=office)
    clients = clients.order_by("system_number", "name", "pk")

    audit_rows = list(BootstrapAudit.objects.select_related("client").filter(
        allowed=False,
        reason__in=ACCESS_NOTIFICATION_REASONS,
    ).order_by("-id")[:200])
    unresolved_ids = {row.device_id for row in audit_rows if not row.client_id and row.device_id}
    clients_by_device: dict[str, ClientAccess] = {}
    for client in (
        ClientAccess.objects.select_related("config_bundle")
        .filter(device_id__in=unresolved_ids)
        .order_by("-active", "pk")
    ):
        clients_by_device.setdefault(client.device_id, client)
    notifications = []
    for audit in audit_rows:
        matched_client = audit.client or clients_by_device.get(audit.device_id)
        row = _audit_row(audit, client_override=matched_client, identity_resolved=True)
        if row["office"].casefold() in HIDDEN_OFFICES:
            continue
        notifications.append(row)
        if len(notifications) >= 80:
            break
    return panel_json({
        "ok": True,
        "offices": offices,
        "office": office,
        "rows": [_client_row(row) for row in clients],
        "notifications": notifications,
        "unread_count": sum(1 for row in notifications if not row["read"]),
    })


def _bundle_ids_for_scope(body: dict[str, Any]) -> tuple[list[int], str]:
    scope = str(body.get("scope") or "office").strip().lower()
    if scope == "device":
        client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
        return [client.config_bundle_id], f"{client.office_name} / {client.system_number}"
    if scope != "office":
        raise ValueError("Choose office or individual PC scope.")
    office = _selected_office(body.get("office"), _visible_offices())
    if not office:
        raise ValueError("Choose an office.")
    ids = list(
        ClientAccess.objects.filter(office_name__iexact=office)
        .values_list("config_bundle_id", flat=True)
        .distinct()
    )
    if not ids:
        raise ValueError("No configuration bundles are assigned to this office.")
    return ids, office


def _proxy_filters(queryset, body: dict[str, Any]):
    provider = str(body.get("provider") or "").strip().upper()
    country = str(body.get("country") or "").strip().upper()
    region = str(body.get("region") or "").strip()
    city = str(body.get("city") or "").strip()
    if provider:
        queryset = queryset.filter(provider_code=provider)
    if country:
        queryset = queryset.filter(country_code=country)
    if region:
        queryset = queryset.filter(region=region)
    if city:
        queryset = queryset.filter(city=city)
    return queryset, provider, country, region, city


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_proxy_api(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        if not request.user.is_superuser:
            return panel_json({"ok": False, "message": "Super-admin access is required."}, status=403)
        try:
            body = _body(request)
            action = str(body.get("action") or "").strip().lower()
            bundle_ids, scope_label = _bundle_ids_for_scope(body)
            if action == "generate":
                provider = str(body.get("provider") or "").strip().upper()
                country = str(body.get("country") or "").strip().upper()
                region = str(body.get("region") or "").strip()[:120]
                city = str(body.get("city") or "").strip()[:120]
                if not Provider.objects.filter(code=provider, active=True).exists():
                    raise ValueError("Choose an active provider.")
                valid_countries = {code for code, _name in country_rows()}
                if country not in valid_countries:
                    raise ValueError("Choose a valid country.")
                target_count = int(body.get("target_count") or 1000)
                threshold = int(body.get("threshold") or min(200, max(1, target_count // 5)))
                if not 1 <= target_count <= 5000 or not 1 <= threshold <= target_count:
                    raise ValueError("Target must be 1-5000 and threshold must not exceed it.")
                bundles = list(ConfigBundle.objects.filter(pk__in=bundle_ids, active=True))
                queued = created = missing = 0
                for bundle in bundles:
                    if not provider_is_configured(provider, bundle.get_payload()):
                        missing += 1
                        continue
                    target, was_created = ProxyPoolTarget.objects.update_or_create(
                        config_bundle=bundle,
                        provider_code=provider,
                        country_code=country,
                        region=region,
                        city=city,
                        defaults={
                            "target_count": target_count,
                            "replenish_below": threshold,
                            "active": True,
                        },
                    )
                    created += int(was_created)
                    queued += int(queue_refill_proxy_pool(target.pk))
                return panel_json({
                    "ok": True,
                    "message": (
                        f"{provider} {country} queued for {scope_label}: {queued} refill(s), "
                        f"{created} new target(s), {missing} bundle(s) missing credentials."
                    ),
                })

            if action == "remove_available":
                if str(body.get("confirmation") or "") != "REMOVE AVAILABLE":
                    raise ValueError("Type REMOVE AVAILABLE to confirm this destructive action.")
                queryset = ProxyPoolTarget.objects.filter(config_bundle_id__in=bundle_ids)
                queryset, provider, country, region, city = _proxy_filters(queryset, body)
                if not provider or not country:
                    raise ValueError("Provider and country are required before removing stock.")
                targets = list(queryset)
                deleted = 0
                with transaction.atomic():
                    for target in targets:
                        count, _ = target.entries.filter(state="available").delete()
                        deleted += count
                        target.active = False
                        target.refill_pending = False
                        target.save(update_fields=("active", "refill_pending", "updated_at"))
                return panel_json({
                    "ok": True,
                    "message": (
                        f"Removed {deleted} available proxy row(s) from {len(targets)} pool(s) "
                        f"for {scope_label}. Reserved history was retained."
                    ),
                })
            raise ValueError("Unknown Proxy action.")
        except (TypeError, ValueError) as exc:
            return panel_json({"ok": False, "message": str(exc)}, status=400)

    offices = _visible_offices()
    office = _selected_office(request.GET.get("office"), offices)
    client_id = str(request.GET.get("client_id") or "").strip()
    clients = list(
        ClientAccess.objects.select_related("config_bundle")
        .filter(office_name__iexact=office)
        .order_by("system_number", "name", "pk")
    ) if office else []
    bundle_ids = {row.config_bundle_id for row in clients}
    grouped: dict[int, dict[str, dict[str, int]]] = defaultdict(dict)
    summary = (
        ProxyPoolTarget.objects.filter(config_bundle_id__in=bundle_ids, active=True)
        .values("config_bundle_id", "provider_code")
        .annotate(
            available=Count("entries", filter=Q(entries__state="available")),
            reserved=Count("entries", filter=Q(entries__state="reserved")),
            locations=Count("id", distinct=True),
        )
    )
    for row in summary:
        grouped[row["config_bundle_id"]][row["provider_code"]] = {
            "available": row["available"],
            "reserved": row["reserved"],
            "locations": row["locations"],
        }

    selected = None
    detail_rows = []
    if client_id:
        selected = next((row for row in clients if str(row.pk) == client_id), None)
    if selected is not None:
        target_rows = (
            ProxyPoolTarget.objects.filter(config_bundle=selected.config_bundle)
            .annotate(
                available=Count("entries", filter=Q(entries__state="available")),
                reserved=Count("entries", filter=Q(entries__state="reserved")),
            )
            .order_by("provider_code", "country_code", "region", "city")
        )
        detail_rows = [
            {
                "id": row.pk,
                "provider": row.provider_code,
                "country": row.country_code,
                "region": row.region or "Any",
                "city": row.city or "Any",
                "available": row.available,
                "reserved": row.reserved,
                "target": row.target_count,
                "active": row.active,
            }
            for row in target_rows
        ]

    provider = str(request.GET.get("provider") or "").strip().upper()
    country = str(request.GET.get("country") or "").strip().upper()
    region = str(request.GET.get("region") or "").strip()
    regions = []
    cities = []
    provider_row = Provider.objects.filter(code=provider, active=True).first()
    if provider_row and country:
        regions = list(
            ProxyRegionCatalog.objects.filter(
                provider=provider_row, country_code=country, active=True
            ).values("region_code", "region_name").order_by("region_name")
        )
        if region:
            cities = list(
                ProxyCityCatalog.objects.filter(
                    provider=provider_row,
                    country_code=country,
                    region_code=region,
                    active=True,
                ).values_list("city_name", flat=True).distinct().order_by("city_name")
            )
    return panel_json({
        "ok": True,
        "offices": offices,
        "office": office,
        "rows": [
            {
                "id": row.pk,
                "system_number": row.system_number,
                "name": row.name,
                "bundle": row.config_bundle.name,
                "active": row.active,
                "providers": grouped.get(row.config_bundle_id, {}),
            }
            for row in clients
        ],
        "selected_client": _client_row(selected) if selected else None,
        "detail_rows": detail_rows,
        "options": {
            "providers": list(
                Provider.objects.filter(active=True).values("code", "display_name").order_by("display_order", "code")
            ),
            "countries": [
                {"code": code, "name": name} for code, name in country_rows()
            ],
            "regions": regions,
            "cities": cities,
        },
    })


def _clean_codes(raw: Any, allowed: set[str], *, upper: bool) -> list[str]:
    if not isinstance(raw, list):
        return []
    result = []
    for value in raw:
        code = str(value or "").strip()
        code = code.upper() if upper else code.lower()
        if code in allowed and code not in result:
            result.append(code)
    return result


def _policy_row(policy: DesktopOfficeAccessPolicy | None, office: str) -> dict[str, Any]:
    return {
        "office": office,
        "active": policy.active if policy else True,
        "providers": list(policy.allowed_provider_codes) if policy else list(DEFAULT_DESKTOP_PROVIDER_CODES),
        "browsers": list(policy.allowed_browser_codes) if policy else list(DEFAULT_DESKTOP_BROWSER_CODES),
        "devices": list(policy.allowed_device_codes) if policy else list(DEFAULT_DESKTOP_DEVICE_CODES),
        "show_logs": bool(policy.show_logs) if policy else False,
        "source": "office" if policy else "global default",
    }


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_optix_api(request: HttpRequest) -> JsonResponse:
    provider_options = list(
        Provider.objects.filter(active=True).values_list("code", flat=True).order_by("display_order", "code")
    ) or list(DEFAULT_DESKTOP_PROVIDER_CODES)
    browser_options = list(DEFAULT_DESKTOP_BROWSER_CODES)
    device_options = list(DEFAULT_DESKTOP_DEVICE_CODES)
    if request.method == "POST":
        try:
            body = _body(request)
            action = str(body.get("action") or "").strip().lower()
            if action == "save_office":
                office = _selected_office(body.get("office"), _visible_offices())
                if not office:
                    raise ValueError("Choose an office.")
                policy, _ = DesktopOfficeAccessPolicy.objects.get_or_create(office_name=office)
                policy.active = bool(body.get("active"))
                policy.allowed_provider_codes = _clean_codes(body.get("providers"), set(provider_options), upper=True)
                policy.allowed_browser_codes = _clean_codes(body.get("browsers"), set(browser_options), upper=True)
                policy.allowed_device_codes = _clean_codes(body.get("devices"), set(device_options), upper=False)
                policy.show_logs = bool(body.get("show_logs"))
                policy.save()
                return panel_json({"ok": True, "message": f"Dollar defaults saved for {office}."})

            client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
            if action == "save_device":
                client.active = bool(body.get("active"))
                client.desktop_permissions_override = bool(body.get("override"))
                client.allowed_provider_codes = _clean_codes(body.get("providers"), set(provider_options), upper=True)
                client.allowed_browser_codes = _clean_codes(body.get("browsers"), set(browser_options), upper=True)
                client.allowed_device_codes = _clean_codes(body.get("devices"), set(device_options), upper=False)
                client.show_logs_override = bool(body.get("show_logs"))
                client.save(update_fields=(
                    "active", "desktop_permissions_override", "allowed_provider_codes",
                    "allowed_browser_codes", "allowed_device_codes", "show_logs_override",
                    "updated_at",
                ))
                return panel_json({"ok": True, "message": f"Dollar access saved for {client.name}."})
            if action == "schedule_uninstall":
                if str(body.get("confirmation") or "").strip() != str(client.system_number):
                    raise ValueError("Enter the exact system number to schedule remote removal.")
                if not client.active:
                    raise ValueError("Enable this PC first so it can securely receive the removal command.")
                client.desktop_remote_action = ClientAccess.REMOTE_ACTION_UNINSTALL
                client.desktop_remote_action_revision += 1
                client.desktop_remote_action_requested_at = timezone.now()
                client.desktop_remote_action_acknowledged_at = None
                client.desktop_remote_action_requested_by = request.user
                client.save(update_fields=(
                    "desktop_remote_action", "desktop_remote_action_revision",
                    "desktop_remote_action_requested_at", "desktop_remote_action_acknowledged_at",
                    "desktop_remote_action_requested_by", "updated_at",
                ))
                return panel_json({
                    "ok": True,
                    "message": "Remote Dollar removal scheduled. The PC will acknowledge it before uninstalling.",
                })
            if action == "cancel_uninstall":
                if client.desktop_remote_action_acknowledged_at is not None:
                    raise ValueError("This command was already acknowledged and can no longer be cancelled.")
                client.desktop_remote_action = ClientAccess.REMOTE_ACTION_NONE
                client.desktop_remote_action_requested_at = None
                client.desktop_remote_action_requested_by = None
                client.save(update_fields=(
                    "desktop_remote_action", "desktop_remote_action_requested_at",
                    "desktop_remote_action_requested_by", "updated_at",
                ))
                return panel_json({"ok": True, "message": "Pending Dollar removal cancelled."})
            raise ValueError("Unknown Dollar action.")
        except ValueError as exc:
            return panel_json({"ok": False, "message": str(exc)}, status=400)

    offices = _visible_offices()
    office = _selected_office(request.GET.get("office"), offices)
    client_id = str(request.GET.get("client_id") or "").strip()
    clients = list(
        ClientAccess.objects.select_related("config_bundle")
        .filter(office_name__iexact=office)
        .order_by("system_number", "name", "pk")
    ) if office else []
    policy = DesktopOfficeAccessPolicy.objects.filter(office_name__iexact=office).first() if office else None
    selected = next((row for row in clients if str(row.pk) == client_id), None)
    selected_row = None
    if selected:
        resolved = DesktopOfficeAccessPolicy.resolve_for(selected)
        selected_row = {
            **_client_row(selected),
            "override": selected.desktop_permissions_override,
            "providers": list(selected.allowed_provider_codes),
            "browsers": list(selected.allowed_browser_codes),
            "devices": list(selected.allowed_device_codes),
            "show_logs": selected.show_logs_override,
            "resolved": resolved,
            "remote_action": selected.desktop_remote_action,
            "remote_action_revision": selected.desktop_remote_action_revision,
            "remote_action_requested_at": iso(selected.desktop_remote_action_requested_at),
            "remote_action_acknowledged_at": iso(selected.desktop_remote_action_acknowledged_at),
        }
    return panel_json({
        "ok": True,
        "offices": offices,
        "office": office,
        "policy": _policy_row(policy, office),
        "rows": [
            {
                "id": row.pk,
                "system_number": row.system_number,
                "name": row.name,
                "bundle": row.config_bundle.name,
                "active": row.active,
                "permission_source": DesktopOfficeAccessPolicy.resolve_for(row)["source"],
                "remote_action": row.desktop_remote_action,
                "remote_acknowledged": row.desktop_remote_action_acknowledged_at is not None,
                "last_seen": iso(row.last_seen_at),
            }
            for row in clients
        ],
        "selected_client": selected_row,
        "options": {
            "providers": provider_options,
            "browsers": browser_options,
            "devices": device_options,
        },
    })

