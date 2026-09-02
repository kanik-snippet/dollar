from __future__ import annotations

import csv
import ipaddress
import json
from datetime import datetime, time, timedelta
from typing import Any

from django.contrib.admin.views.decorators import staff_member_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Max, Prefetch, Q, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.views.decorators.http import require_GET, require_http_methods

from .subadmin_views import _parse_ipv4_values, _save_client_ip_values

from .models import (
    BootstrapAudit,
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    ExtensionPackage,
    ProfileActivity,
    ProfileDomainActivity,
    MonitoredDomain,
    Provider,
    ProxyGenerationJob,
    ProxyPoolEntry,
    SubAdminAccount,
    SubAdminDomainExclusion,
    SubAdminScopeExclusion,
)


PROFILE_OPEN_STATUSES = {"profile_opened", "opened"}
PROFILE_DELETE_STATUSES = {"profile_deleted", "deleted", "profile_delete_completed"}


def profile_display_name(row: Any) -> str:
    """Return the readable profile label used throughout the control panel."""
    candidates = (
        getattr(row, "profile_name", ""),
        getattr(getattr(row, "reservation", None), "profile_name", ""),
        getattr(getattr(row, "client", None), "profile_name", ""),
        getattr(getattr(row, "client", None), "name", ""),
        getattr(row, "profile_id", ""),
    )
    for value in candidates:
        value = str(value or "").strip()
        if value:
            return value
    return "Unnamed"

def panel_json(payload: dict[str, Any], status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def profiles_opened_last_24h(
    request: HttpRequest | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> int:
    """Return the canonical profile-open count used by every panel view.

    Overview treats a successful ``profile_opened`` audit as the source of
    truth. Keeping Domain Activity on this same query prevents drift caused by
    local-midnight boundaries or deletion events.
    """
    if start is None:
        start = timezone.now() - timedelta(hours=24)
    if end is None:
        end = timezone.now()
    queryset = ProfileActivity.objects.filter(
        status__in=PROFILE_OPEN_STATUSES, created_at__gte=start, created_at__lt=end
    )
    if request is not None:
        office = str(request.GET.get("office") or "").strip()
        client_id = str(request.GET.get("client") or "").strip()
        group = str(request.GET.get("group") or "").strip()
        if office:
            queryset = queryset.filter(client__office_name=office)
        if client_id:
            queryset = queryset.filter(client_id=client_id)
        if group:
            queryset = queryset.filter(group_id=group)
    return queryset.count()


def iso(value: datetime | None) -> str:
    if value is None:
        return ""
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.isoformat()


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, parsed))


def admin_change(model_name: str, object_id: int) -> str:
    return reverse(f"admin:control_{model_name}_change", args=(object_id,))


def domain_range(request: HttpRequest) -> tuple[datetime, datetime, str]:
    now = timezone.now()
    preset = str(request.GET.get("range") or "7d").strip().lower()
    preset_days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
    start = now - timedelta(days=preset_days.get(preset, 7))
    end = now
    from_value = str(request.GET.get("from") or "").strip()
    to_value = str(request.GET.get("to") or "").strip()
    if from_value:
        parsed = parse_datetime(from_value)
        if parsed is None:
            parsed_date = parse_date(from_value)
            if parsed_date is not None:
                parsed = datetime.combine(parsed_date, time.min)
        if parsed is not None:
            start = timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed
            preset = "custom"
    if to_value:
        parsed = parse_datetime(to_value)
        if parsed is None:
            parsed_date = parse_date(to_value)
            if parsed_date is not None:
                parsed = datetime.combine(parsed_date + timedelta(days=1), time.min)
        if parsed is not None:
            end = timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed
            preset = "custom"
    if start >= end:
        start = end - timedelta(days=7)
    return start, end, preset


def domain_queryset(request: HttpRequest):
    start, end, preset = domain_range(request)
    queryset = ProfileDomainActivity.objects.select_related(
        "client", "job", "reservation"
    ).filter(last_visited_at__gte=start, last_visited_at__lt=end)
    exact_filters = {
        "client_id": "client",
        "client__office_name": "office",
        "client__ipv4": "ip",
        "client__device_id": "device",
        "group_id": "group",
        "profile_id": "profile_id",
        "session_id": "session",
    }
    for field, parameter in exact_filters.items():
        value = str(request.GET.get(parameter) or "").strip()
        if value:
            queryset = queryset.filter(**{field: value})
    domain = str(request.GET.get("domain") or "").strip()
    if domain:
        queryset = queryset.filter(domain__icontains=domain)
    profile_name = str(request.GET.get("profile_name") or "").strip()
    if profile_name:
        queryset = queryset.filter(profile_name__icontains=profile_name)
    query = str(request.GET.get("q") or "").strip()
    if query:
        queryset = queryset.filter(
            Q(domain__icontains=query)
            | Q(client__name__icontains=query)
            | Q(client__office_name__icontains=query)
            | Q(client__device_id__icontains=query)
            | Q(client__ipv4__icontains=query)
            | Q(profile_name__icontains=query)
            | Q(profile_id__icontains=query)
            | Q(browser_id__icontains=query)
            | Q(session_id__icontains=query)
        )
    return queryset, start, end, preset


def domain_row(row: ProfileDomainActivity) -> dict[str, Any]:
    duration = max(
        0, int((row.session_ended_at - row.session_started_at).total_seconds())
    )
    return {
        "id": row.pk,
        "domain": row.domain,
        "visit_count": row.visit_count,
        "first_visited_at": iso(row.first_visited_at),
        "last_visited_at": iso(row.last_visited_at),
        "session_started_at": iso(row.session_started_at),
        "session_ended_at": iso(row.session_ended_at),
        "session_duration_seconds": duration,
        "session_id": row.session_id,
        "group_id": row.group_id,
        "profile_name": profile_display_name(row),
        "profile_id": row.profile_id,
        "browser_id": row.browser_id,
        "client_id": row.client_id,
        "client_name": row.client.name,
        "office_name": row.client.office_name,
        "system_number": row.client.system_number,
        "ipv4": str(row.client.ipv4),
        "device_id": row.client.device_id,
        "job_id": row.job_id,
        "reservation_id": row.reservation_id,
        "admin_url": admin_change("profiledomainactivity", row.pk),
    }


def suspicious_queryset(request: HttpRequest):
    queryset, start, end, preset = domain_queryset(request)
    monitored = list(
        MonitoredDomain.objects.filter(active=True).values_list("domain", flat=True)
    )
    return queryset.filter(domain__in=monitored), start, end, preset, monitored
@staff_member_required(login_url="admin:login")
@require_GET
def panel(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "control/panel.html",
        {
            "panel_title": "Automation Control Center",
            "admin_url": reverse("admin:index"),
            "logout_url": reverse("admin:logout"),
        },
    )


def _office_ip_whitelist_offices() -> list[str]:
    """Return offices that currently have at least one active client."""
    return list(
        ClientAccess.objects.filter(active=True)
        .exclude(office_name="")
        .values_list("office_name", flat=True)
        .distinct()
        .order_by("office_name")
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_office_ip_whitelist(request: HttpRequest) -> HttpResponse:
    """Render the simple office-wide additional-IP whitelist tool."""
    return render(
        request,
        "control/office_ip_whitelist.html",
        {
            "offices": _office_ip_whitelist_offices(),
            "panel_url": reverse("control:panel"),
            "api_url": reverse("control:panel-office-ip-whitelist-api"),
        },
    )


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_office_ip_whitelist_api(request: HttpRequest) -> JsonResponse:
    """Add one allowed IPv4 to every active device in a selected office.

    The primary ClientAccess IPv4 remains untouched.  The submitted address is
    stored only as an active ClientAccessIP record when it differs from that
    device's primary address.
    """
    if request.method == "GET":
        return panel_json({"ok": True, "offices": _office_ip_whitelist_offices()})

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return panel_json({"ok": False, "message": "Invalid JSON body."}, status=400)
    if not isinstance(body, dict):
        return panel_json({"ok": False, "message": "JSON body must be an object."}, status=400)

    office = str(body.get("office") or "").strip()
    raw_ip = str(body.get("ipv4") or "").strip()
    if not office:
        return panel_json({"ok": False, "message": "Choose an office."}, status=400)
    try:
        parsed = ipaddress.ip_address(raw_ip)
    except ValueError:
        return panel_json({"ok": False, "message": "Enter a valid IPv4 address."}, status=400)
    if not isinstance(parsed, ipaddress.IPv4Address):
        return panel_json({"ok": False, "message": "Only IPv4 addresses are supported."}, status=400)
    normalized_ip = str(parsed)

    clients = list(
        ClientAccess.objects.filter(office_name__iexact=office, active=True)
        .only("id", "ipv4")
        .order_by("pk")
    )
    if not clients:
        return panel_json(
            {"ok": False, "message": "No active devices exist in that office."},
            status=404,
        )

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

    result = {
        "office": office,
        "ipv4": normalized_ip,
        "devices": len(clients),
        "created": created,
        "reactivated": reactivated,
        "primary_ip_skipped": primary_skipped,
        "existing_additional_skipped": existing_skipped,
    }
    return panel_json(
        {
            "ok": True,
            "message": f"{normalized_ip} is allowed for {office}.",
            "result": result,
        }
    )


def _panel_datetime_bound(value: Any):
    parsed = parse_datetime(str(value or "").strip())
    if parsed is None:
        return None
    return timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed


def _panel_device_row(row: ClientAccess) -> dict[str, Any]:
    additional = [str(item.ipv4) for item in getattr(row, "active_allowed_ips", [])]
    return {
        "id": row.pk, "name": row.name, "office": row.office_name,
        "system": row.system_number, "ipv4": str(row.ipv4),
        "additional_ips": additional, "device_id": row.device_id,
        "profile_name": row.profile_name or row.name, "config": row.config_bundle.name,
        "group_name": row.config_bundle.browser_group_name,
        "group_id": row.config_bundle.browser_group_id, "active": row.active,
        "last_seen": iso(row.last_seen_at), "created_at": iso(row.created_at),
        "admin_url": admin_change("clientaccess", row.pk),
    }


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_devices_api(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return panel_json({"ok": False, "message": "Invalid JSON body."}, status=400)
        if not isinstance(body, dict):
            return panel_json({"ok": False, "message": "JSON body must be an object."}, status=400)
        action = str(body.get("action") or "").strip().lower()
        try:
            if action == "toggle":
                client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
                client.active = bool(body.get("active"))
                client.save(update_fields=("active", "updated_at"))
                return panel_json({"ok": True, "message": f"{client.name} access updated."})
            if action == "update_ips":
                client = get_object_or_404(ClientAccess, pk=body.get("client_id"))
                parsed_ips = _parse_ipv4_values(body.get("ipv4") or [])
                _save_client_ip_values(client, parsed_ips)
                return panel_json({"ok": True, "message": f"IP access saved for {client.name}."})
            if action == "bulk_office":
                office = str(body.get("office") or "").strip()
                if not office:
                    raise ValueError("Choose an office.")
                parsed_ips = _parse_ipv4_values(body.get("ipv4") or [])
                targets = list(ClientAccess.objects.filter(office_name__iexact=office))
                if not targets:
                    raise ValueError("No devices exist in that office.")
                with transaction.atomic():
                    for client in targets:
                        _save_client_ip_values(client, parsed_ips)
                return panel_json({"ok": True, "message": f"IP access saved for {len(targets)} device(s)."})
            return panel_json({"ok": False, "message": "Unknown device action."}, status=400)
        except (ValueError, ValidationError) as exc:
            return panel_json({"ok": False, "message": str(exc)}, status=400)

    queryset = ClientAccess.objects.select_related("config_bundle").prefetch_related(
        Prefetch("allowed_ips", queryset=ClientAccessIP.objects.filter(active=True), to_attr="active_allowed_ips")
    )


    query = str(request.GET.get("q") or "").strip()
    office = str(request.GET.get("office") or "").strip()
    active = str(request.GET.get("active") or "").strip().lower()
    if query:
        queryset = queryset.filter(Q(name__icontains=query) | Q(ipv4__icontains=query) | Q(device_id__icontains=query) | Q(office_name__icontains=query) | Q(system_number__icontains=query) | Q(profile_name__icontains=query))
    if office:
        queryset = queryset.filter(office_name__iexact=office)
    if active in {"1", "0"}:
        queryset = queryset.filter(active=active == "1")
    start = _panel_datetime_bound(request.GET.get("from"))
    end = _panel_datetime_bound(request.GET.get("to"))
    if start:
        queryset = queryset.filter(last_seen_at__gte=start)
    if end:
        queryset = queryset.filter(last_seen_at__lte=end)
    queryset = queryset.order_by("office_name", "system_number", "name")
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    offices = list(ClientAccess.objects.exclude(office_name="").values_list("office_name", flat=True).distinct().order_by("office_name"))
    aggregate = queryset.aggregate(total=Count("id"), active=Count("id", filter=Q(active=True)), seen=Count("id", filter=Q(last_seen_at__isnull=False)))
    return panel_json({"rows": [_panel_device_row(row) for row in page.object_list], "offices": offices, "filters": {"q": query, "office": office, "active": active, "from": str(request.GET.get("from") or ""), "to": str(request.GET.get("to") or "")}, "metrics": {"total": aggregate["total"] or 0, "active": aggregate["active"] or 0, "seen": aggregate["seen"] or 0}, "pagination": {"page": page.number, "pages": paginator.num_pages, "page_size": page_size, "total": paginator.count, "has_previous": page.has_previous(), "has_next": page.has_next()}})


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_subadmins_api(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return panel_json({"ok": False, "message": "Invalid JSON body."}, status=400)
        account = get_object_or_404(SubAdminAccount, pk=body.get("account_id"))
        offices = [str(value).strip().casefold() for value in (body.get("excluded_offices") or []) if str(value).strip()]
        groups = [str(value).strip().casefold() for value in (body.get("excluded_groups") or []) if str(value).strip()]
        domains = [str(value).strip().casefold().rstrip(".") for value in (body.get("excluded_domains") or []) if str(value).strip()]
        with transaction.atomic():
            if "active" in body:
                account.active = bool(body.get("active"))
                account.save(update_fields=("active",))
            SubAdminScopeExclusion.objects.filter(account=account).delete()
            SubAdminScopeExclusion.objects.bulk_create([SubAdminScopeExclusion(account=account, scope_type="office", value=value) for value in offices] + [SubAdminScopeExclusion(account=account, scope_type="group", value=value) for value in groups])
            SubAdminDomainExclusion.objects.filter(account=account).delete()
            for domain in domains:
                SubAdminDomainExclusion.objects.create(account=account, domain=domain)
        return panel_json({"ok": True, "message": f"Visibility saved for {account}."})
    accounts = []
    for account in SubAdminAccount.objects.select_related("user").prefetch_related("scope_exclusions", "domain_exclusions"):
        scopes = list(account.scope_exclusions.all())
        accounts.append({"id": account.pk, "username": account.user.username, "display_name": account.display_name or account.user.username, "active": account.active, "excluded_offices": [row.value for row in scopes if row.scope_type == "office"], "excluded_groups": [row.value for row in scopes if row.scope_type == "group"], "excluded_domains": [row.domain for row in account.domain_exclusions.all() if row.active]})
    office_options = list(ClientAccess.objects.exclude(office_name="").values_list("office_name", flat=True).distinct().order_by("office_name"))
    group_options = list(ConfigBundle.objects.exclude(browser_group_id="").values("browser_group_id", "browser_group_name").distinct().order_by("browser_group_name"))
    return panel_json({"accounts": accounts, "office_options": office_options, "group_options": group_options})

@staff_member_required(login_url="admin:login")
@require_GET
def panel_office_audit(request: HttpRequest) -> HttpResponse:
    """Render a source-of-truth, office-scoped profile lifecycle audit."""
    start, end, preset = domain_range(request)
    offices = list(
        ClientAccess.objects.exclude(office_name="")
        .values_list("office_name", flat=True)
        .distinct()
        .order_by("office_name")
    )
    office = str(request.GET.get("office") or "").strip()
    if office not in offices:
        office = offices[0] if offices else ""

    jobs = ProxyGenerationJob.objects.select_related("client").filter(
        created_at__gte=start, created_at__lt=end
    )
    activities = ProfileActivity.objects.select_related("client", "job", "reservation").filter(
        created_at__gte=start, created_at__lt=end
    )
    domains = ProfileDomainActivity.objects.select_related("client").filter(
        last_visited_at__gte=start, last_visited_at__lt=end
    )
    if office:
        jobs = jobs.filter(client__office_name=office)
        activities = activities.filter(client__office_name=office)
        domains = domains.filter(client__office_name=office)

    all_jobs = list(jobs.order_by("-created_at", "-id"))
    jobs = all_jobs[:500]
    activity_rows = list(activities.order_by("-created_at", "-id"))
    opened_ids = {
        (row.client_id, row.profile_id)
        for row in activity_rows
        if row.status.casefold() in PROFILE_OPEN_STATUSES and row.profile_id
    }
    deleted_ids = {
        (row.client_id, row.profile_id)
        for row in activity_rows
        if row.status.casefold() in PROFILE_DELETE_STATUSES and row.profile_id
    }
    opened_by_job: dict[int, set[tuple[int, str]]] = {}
    deleted_by_job: dict[int, set[tuple[int, str]]] = {}
    for row in activity_rows:
        key = (row.client_id, row.profile_id)
        if not row.job_id or not row.profile_id:
            continue
        if row.status.casefold() in PROFILE_OPEN_STATUSES:
            opened_by_job.setdefault(row.job_id, set()).add(key)
        if row.status.casefold() in PROFILE_DELETE_STATUSES:
            deleted_by_job.setdefault(row.job_id, set()).add(key)

    submitted_total = sum(getattr(job, "submitted_count", job.requested_count) for job in all_jobs)
    accepted_total = sum(job.requested_count for job in all_jobs)
    opened_total = len(opened_ids)
    deleted_total = len(deleted_ids & opened_ids)

    default_domains = {
        "ipapi.co",
        "www.ipapi.co",
        "ipwho.is",
        "www.ipwho.is",
    }
    profile_domains: dict[tuple[int, str], set[str]] = {}
    profile_meta: dict[tuple[int, str], ProfileDomainActivity] = {}
    for row in domains:
        key = (row.client_id, row.profile_id)
        profile_domains.setdefault(key, set()).add(row.domain.casefold())
        current = profile_meta.get(key)
        if current is None or row.last_visited_at > current.last_visited_at:
            profile_meta[key] = row
    default_only = []
    for key, domain_set in profile_domains.items():
        if domain_set and domain_set.issubset(default_domains):
            row = profile_meta[key]
            default_only.append({
                "time": row.last_visited_at,
                "device": row.client.name,
                "office": row.client.office_name,
                "system": row.client.system_number,
                "profile_name": row.profile_name or row.profile_id,
                "profile_id": row.profile_id,
                "domains": ", ".join(sorted(domain_set)),
            })
    default_only.sort(key=lambda row: row["time"], reverse=True)

    job_rows = []
    for job in jobs:
        opened = len(opened_by_job.get(job.id, set()))
        deleted = len(deleted_by_job.get(job.id, set()) & opened_by_job.get(job.id, set()))
        job_rows.append({
            "id": job.id,
            "time": job.created_at,
            "device": job.client.name,
            "system": job.client.system_number,
            "provider": job.provider_code,
            "country": job.country_code,
            "submitted": getattr(job, "submitted_count", job.requested_count),
            "accepted": job.requested_count,
            "opened": opened,
            "deleted": deleted,
            "pending_delete": max(0, opened - deleted),
            "status": job.status,
        })
    lifecycle_rows = [
        {
            "time": row.created_at,
            "device": row.client.name,
            "system": row.client.system_number,
            "status": row.status,
            "profile_name": row.profile_name or row.profile_id,
            "profile_id": row.profile_id,
            "job_id": row.job_id or "",
            "detail": row.detail,
        }
        for row in activity_rows[:1000]
    ]
    return render(request, "control/office_audit.html", {
        "panel_title": "Office profile audit",
        "admin_url": reverse("admin:index"),
        "logout_url": reverse("admin:logout"),
        "office_options": offices,
        "selected_office": office,
        "selected_preset": preset,
        "from_value": request.GET.get("from", ""),
        "to_value": request.GET.get("to", ""),
        "range_from": start,
        "range_to": end,
        "metrics": {
            "commands": len(all_jobs),
            "submitted": submitted_total,
            "accepted": accepted_total,
            "opened": opened_total,
            "deleted": deleted_total,
            "pending_delete": max(0, opened_total - deleted_total),
            "open_gap": max(0, accepted_total - opened_total),
            "default_only": len(default_only),
        },
        "job_total": len(all_jobs),
        "job_rows": job_rows,
        "lifecycle_rows": lifecycle_rows,
        "default_only_rows": default_only[:500],
    })
@staff_member_required(login_url="admin:login")
@require_GET
def panel_overview_api(request: HttpRequest) -> JsonResponse:
    now = timezone.now()
    since = now - timedelta(hours=24)
    domain_recent = ProfileDomainActivity.objects.filter(last_visited_at__gte=since)
    domain_totals = domain_recent.aggregate(
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    job_status = {
        row["status"]: row["count"]
        for row in ProxyGenerationJob.objects.values("status").annotate(count=Count("id"))
    }
    pool_status = {
        row["state"]: row["count"]
        for row in ProxyPoolEntry.objects.values("state").annotate(count=Count("id"))
    }
    bootstrap_status = BootstrapAudit.objects.filter(created_at__gte=since).aggregate(
        total=Count("id"),
        allowed_count=Count("id", filter=Q(allowed=True)),
        denied_count=Count("id", filter=Q(allowed=False)),
    )
    recent_domains = [
        domain_row(row)
        for row in ProfileDomainActivity.objects.select_related(
            "client", "job", "reservation"
        ).order_by("-last_visited_at")[:8]
    ]
    monitored_domains = list(
        MonitoredDomain.objects.filter(active=True).values_list("domain", flat=True)
    )
    suspicious_recent = [
        domain_row(row)
        for row in ProfileDomainActivity.objects.select_related("client")
        .filter(domain__in=monitored_domains, last_visited_at__gte=since)
        .order_by("-last_visited_at")[:8]
    ]
    office_rows = ClientAccess.objects.values("office_name").annotate(
        devices=Count("id"),
        active_devices=Count("id", filter=Q(active=True)),
        last_seen=Max("last_seen_at"),
    ).order_by("office_name")
    offices = [
        {
            "office_name": row["office_name"],
            "devices": row["devices"],
            "active_devices": row["active_devices"],
            "last_seen_at": iso(row["last_seen"]),
        }
        for row in office_rows
    ]
    return panel_json(
        {
            "generated_at": iso(now),
            "cards": {
                "devices": ClientAccess.objects.count(),
                "active_devices": ClientAccess.objects.filter(active=True).count(),
                "online_24h": ClientAccess.objects.filter(
                    active=True, last_seen_at__gte=since
                ).count(),
                "profiles_opened_24h": profiles_opened_last_24h(),
                "domain_visits_24h": domain_totals["visits"] or 0,
                "unique_domains_24h": domain_totals["domains"] or 0,
                "sessions_24h": domain_totals["sessions"] or 0,
                "available_proxies": pool_status.get("available", 0),
                "suspicious_activity_24h": ProfileDomainActivity.objects.filter(
                    domain__in=monitored_domains, last_visited_at__gte=since
                ).count(),
            },
            "job_status": job_status,
            "pool_status": pool_status,
            "bootstrap_status": {
                "total": bootstrap_status["total"],
                "allowed": bootstrap_status["allowed_count"],
                "denied": bootstrap_status["denied_count"],
            },
            "recent_domains": recent_domains,
            "suspicious_recent": suspicious_recent,
            "monitored_domains": monitored_domains,
            "offices": offices,
            "management": [
                {"key": "devices", "label": "Devices", "count": ClientAccess.objects.count(), "description": "Whitelisted systems and assignments"},
                {"key": "configurations", "label": "Config bundles", "count": ConfigBundle.objects.count(), "description": "Runtime configuration and groups"},
                {"key": "providers", "label": "Providers", "count": Provider.objects.count(), "description": "Providers and country catalogs"},
                {"key": "extensions", "label": "Extensions", "count": ExtensionPackage.objects.count(), "description": "Managed browser packages"},
            ],
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_suspicious_activity_api(request: HttpRequest) -> JsonResponse:
    queryset, start, end, preset, monitored = suspicious_queryset(request)
    aggregate = queryset.aggregate(
        records=Count("id"),
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        clients=Count("client_id", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    queryset = queryset.order_by("-last_visited_at", "-id")
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(
        bounded_int(request.GET.get("page"), 1, 1, 1000000)
    )
    return panel_json({
        "range": {"preset": preset, "from": iso(start), "to": iso(end)},
        "monitored_domains": monitored,
        "metrics": {
            key: aggregate[key] or 0
            for key in ("records", "visits", "domains", "clients", "profiles", "sessions")
        },
        "rows": [domain_row(row) for row in page.object_list],
        "pagination": {
            "page": page.number, "pages": paginator.num_pages,
            "page_size": page_size, "total": paginator.count,
            "has_previous": page.has_previous(), "has_next": page.has_next(),
        },
        "monitor_admin_url": reverse("admin:control_monitoreddomain_changelist"),
    })
@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_api(request: HttpRequest) -> JsonResponse:
    queryset, start, end, preset = domain_queryset(request)
    aggregate = queryset.aggregate(
        records=Count("id"),
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        clients=Count("client_id", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    # Keep this card on the exact same canonical query as Overview. The former
    # local-midnight/deletion-event query could disagree with the known-good
    # Overview total.
    opened_today = profiles_opened_last_24h(request, start, end)
    top_domains = queryset.values("domain").annotate(
        visits=Sum("visit_count"),
        sessions=Count("session_id", distinct=True),
        clients=Count("client_id", distinct=True),
        last_seen_at=Max("last_visited_at"),
    ).order_by("-visits", "domain")[:10]
    top_domain_rows = [
        {**row, "last_seen_at": iso(row["last_seen_at"])} for row in top_domains
    ]
    sort_map = {
        "last_seen": "-last_visited_at",
        "first_seen": "first_visited_at",
        "visits": "-visit_count",
        "domain": "domain",
        "device": "client__name",
    }
    sort = str(request.GET.get("sort") or "last_seen")
    queryset = queryset.order_by(sort_map.get(sort, "-last_visited_at"), "-id")
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    office_source = ClientAccess.objects.all()
    group_source = ProfileDomainActivity.objects.all()
    options = {
        "offices": list(
            office_source.exclude(office_name="")
            .values_list("office_name", flat=True)
            .distinct().order_by("office_name")[:200]
        ),
        "groups": list(
            group_source.exclude(group_id="")
            .values_list("group_id", flat=True)
            .distinct().order_by("group_id")[:200]
        ),
        "clients": [
            {
                "id": row.pk,
                "name": row.name,
                "office_name": row.office_name,
                "system_number": row.system_number,
                "ipv4": str(row.ipv4),
                "device_id": row.device_id,
            }
            for row in ClientAccess.objects.order_by(
                "office_name", "system_number", "name"
            )[:500]
        ],
    }
    return panel_json(
        {
            "range": {"preset": preset, "from": iso(start), "to": iso(end)},
            "metrics": {
                "records": aggregate["records"] or 0,
                "visits": aggregate["visits"] or 0,
                "unique_domains": aggregate["domains"] or 0,
                "devices": aggregate["clients"] or 0,
                "profiles": aggregate["profiles"] or 0,
                "profiles_opened_today": opened_today,
                "sessions": aggregate["sessions"] or 0,
            },
            "top_domains": top_domain_rows,
            "rows": [domain_row(row) for row in page.object_list],
            "pagination": {
                "page": page.number,
                "pages": paginator.num_pages,
                "page_size": page_size,
                "total": paginator.count,
                "has_previous": page.has_previous(),
                "has_next": page.has_next(),
            },
            "options": options,
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_detail_api(
    request: HttpRequest, activity_id: int
) -> JsonResponse:
    row = get_object_or_404(
        ProfileDomainActivity.objects.select_related("client", "job", "reservation"),
        pk=activity_id,
    )
    session_rows = ProfileDomainActivity.objects.filter(
        client_id=row.client_id,
        profile_id=row.profile_id,
        session_id=row.session_id,
    ).order_by("first_visited_at", "domain").values(
        "id", "domain", "visit_count", "first_visited_at", "last_visited_at"
    )
    return panel_json(
        {
            "activity": domain_row(row),
            "session_domains": [
                {
                    "id": item["id"],
                    "domain": item["domain"],
                    "visit_count": item["visit_count"],
                    "first_visited_at": iso(item["first_visited_at"]),
                    "last_visited_at": iso(item["last_visited_at"]),
                }
                for item in session_rows
            ],
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_export(request: HttpRequest) -> HttpResponse:
    queryset, start, end, _preset = domain_queryset(request)
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M")
    response["Content-Disposition"] = f'attachment; filename="domain-activity-{stamp}.csv"'
    writer = csv.writer(response)
    writer.writerow([
        "Domain", "Visits", "First visited", "Last visited", "Session started",
        "Session ended", "Office", "System", "Device name", "IPv4", "Device ID",
        "Group ID", "Profile name", "Profile ID", "Browser ID", "Session ID",
        "Job ID", "Reservation ID", "Range from", "Range to",
    ])
    for row in queryset.order_by("-last_visited_at").iterator(chunk_size=2000):
        writer.writerow([
            row.domain, row.visit_count, iso(row.first_visited_at),
            iso(row.last_visited_at), iso(row.session_started_at),
            iso(row.session_ended_at), row.client.office_name,
            row.client.system_number, row.client.name, row.client.ipv4,
            row.client.device_id, row.group_id, profile_display_name(row), row.profile_id,
            row.browser_id, row.session_id, row.job_id or "",
            row.reservation_id or "", iso(start), iso(end),
        ])
    return response
