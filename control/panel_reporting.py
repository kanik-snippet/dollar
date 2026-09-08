"""Read-only office reports and independently refreshed access notifications."""
from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q, Sum
from django.views.decorators.http import require_GET

from .models import BootstrapAudit, ClientAccess, ProfileActivity, ProfileDomainActivity, ProxyGenerationJob
from .panel_views import bounded_int, domain_range, domain_row, iso, panel_json

# Navigation only: never creates offices/devices or copies another server's data.
REPORT_OFFICES = ("APIQTN", "IPLV", "MH", "Quantish Spaze", "Spaze 822", "Welldone 011")
HIDE_PERSONAL = False
OPEN_STATUSES = ("profile_opened", "opened")


def _scope(request):
    offices = list(REPORT_OFFICES)
    # Dollar's own assignments are independent of Warrior, including its test PCs.
    assigned_offices = list(ClientAccess.objects.exclude(office_name="").order_by("office_name").values_list("office_name", flat=True).distinct())
    for name in assigned_offices:
        if str(name).casefold() not in {office.casefold() for office in offices}:
            offices.append(name)
    requested = str(request.GET.get("office") or "").strip()
    default_office = next((name for name in offices if name in assigned_offices), offices[0])
    office = next((name for name in offices if name.casefold() == requested.casefold()), default_office)
    clients = ClientAccess.objects.filter(office_name__iexact=office)
    client_id = str(request.GET.get("client") or "").strip()
    if client_id:
        valid = client_id.isascii() and client_id.isdigit() and len(client_id) <= 19
        clients = clients.filter(pk=int(client_id)) if valid and 0 < int(client_id) < 2**63 else clients.none()
    return offices, office, clients


def _page(queryset, request):
    paginator = Paginator(queryset, bounded_int(request.GET.get("page_size"), 25, 10, 100))
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    return page, {
        "page": page.number, "pages": paginator.num_pages, "total": paginator.count,
        "has_previous": page.has_previous(), "has_next": page.has_next(),
    }


def _unique_profiles(queryset):
    return queryset.exclude(profile_id="").order_by().values("client_id", "profile_id").distinct().count()


@staff_member_required(login_url="admin:login")
@require_GET
def office_audit_api(request):
    offices, office, clients = _scope(request)
    start, end, preset = domain_range(request)
    events = ProfileActivity.objects.filter(client__in=clients, created_at__gte=start, created_at__lt=end)
    jobs = ProxyGenerationJob.objects.filter(client__in=clients, created_at__gte=start, created_at__lt=end)
    totals = jobs.aggregate(requests=Count("id"), submitted=Sum("submitted_count"))
    # Reserved events are attempts, not proof of a browser opening.
    metrics = {
        "systems": clients.count(),
        "proxy_requests": totals["requests"] or 0,
        "submitted": totals["submitted"] or 0,
        "attempts": events.filter(status="proxy_reserved").count(),
        "opened": _unique_profiles(events.filter(status__in=OPEN_STATUSES)),
        "open_events": events.filter(status__in=OPEN_STATUSES).count(),
    }
    view = request.GET.get("view", "systems")
    if view == "events":
        page, pagination = _page(events.select_related("client").order_by("-created_at", "-pk"), request)
        rows = [{
            "id": row.pk, "system": row.client.system_number, "name": row.client.name,
            "profile_id": row.profile_id, "profile_name": row.profile_name,
            "status": row.status, "time": iso(row.created_at),
        } for row in page.object_list]
    else:
        view = "systems"
        page, pagination = _page(clients.select_related("config_bundle").order_by("system_number", "pk"), request)
        page_clients = list(page.object_list)
        ids = [row.pk for row in page_clients]
        counts = {row["client_id"]: row for row in events.filter(client_id__in=ids).order_by().values("client_id").annotate(
            attempts=Count("id", filter=Q(status="proxy_reserved")),
            opened=Count("profile_id", distinct=True, filter=Q(status__in=OPEN_STATUSES) & ~Q(profile_id="")),
            last_activity=Max("created_at"),
        )}
        requests = {row["client_id"]: row for row in jobs.filter(client_id__in=ids).order_by().values("client_id").annotate(
            requests=Count("id"), submitted=Sum("submitted_count"),
        )}
        rows = []
        for client in page_clients:
            count, job = counts.get(client.pk, {}), requests.get(client.pk, {})
            rows.append({
                "id": client.pk, "office": client.office_name, "system": client.system_number,
                "name": client.name, "bundle": client.config_bundle.name,
                "attempts": count.get("attempts", 0), "opened": count.get("opened", 0),
                "proxy_requests": job.get("requests", 0), "submitted": job.get("submitted", 0),
                "last_activity": iso(count.get("last_activity")),
            })
    return panel_json({
        "ok": True, "offices": offices, "office": office, "view": view,
        "range": {"preset": preset, "from": iso(start), "to": iso(end)},
        "metrics": metrics, "rows": rows, "pagination": pagination,
        "proxy_relay": bool(getattr(settings, "WARRIOR_PROXY_BRIDGE_URL", "")),
        "note": "Counts reflect reports received by this server. Attempts are proxy-reserved events; opened profiles are distinct per PC and profile ID in this period. Missing reports are not proof of zero actual usage.",
    })


@staff_member_required(login_url="admin:login")
@require_GET
def domain_activity_api(request):
    offices, office, clients = _scope(request)
    start, end, preset = domain_range(request)
    queryset = ProfileDomainActivity.objects.filter(client__in=clients, last_visited_at__gte=start, last_visited_at__lt=end)
    query = str(request.GET.get("q") or "").strip()[:160]
    if query:
        queryset = queryset.filter(Q(domain__icontains=query) | Q(client__system_number__icontains=query) | Q(profile_name__icontains=query) | Q(profile_id__icontains=query))
    aggregate = queryset.aggregate(visits=Sum("visit_count"), domains=Count("domain", distinct=True), devices=Count("client_id", distinct=True))
    page, pagination = _page(queryset.select_related("client", "reservation").order_by("-last_visited_at", "-pk"), request)
    return panel_json({
        "ok": True, "offices": offices, "office": office, "query": query,
        "range": {"preset": preset, "from": iso(start), "to": iso(end)},
        "metrics": {"visits": aggregate["visits"] or 0, "domains": aggregate["domains"] or 0, "systems": aggregate["devices"] or 0, "profiles": _unique_profiles(queryset)},
        "rows": [domain_row(row) for row in page.object_list], "pagination": pagination,
        "note": "Recorded hostnames from tool profiles only. Full URL paths, query strings and unreported browsing are not stored here. Visits are the reported session totals for records last visited within this period.",
    })


def notifications_data(request):
    from .panel_operations import _audit_row
    # Personal is excluded from office device tabs, not from security alerts.
    # Unread total is independent of the current page; history is never deleted.
    queryset = BootstrapAudit.objects.filter(allowed=False)
    unread = queryset.filter(read_at__isnull=True).count()
    mode = request.GET.get("notification_filter", "unread")
    if mode == "unread":
        queryset = queryset.filter(read_at__isnull=True)
    page, pagination = _page(queryset.select_related("client").order_by("-pk"), request)
    audits = list(page.object_list)
    unresolved = {row.device_id for row in audits if not row.client_id and row.device_id}
    identities = {}
    for client in ClientAccess.objects.filter(device_id__in=unresolved).order_by("-active", "pk"):
        identities.setdefault(client.device_id, client)
    rows = [_audit_row(row, client_override=row.client or identities.get(row.device_id), identity_resolved=True) for row in audits]
    return {"ok": True, "notifications": rows, "unread_count": unread, "pagination": pagination, "notification_filter": mode,
            "scope_note": "Includes Personal and unassigned devices on this server."}


@staff_member_required(login_url="admin:login")
@require_GET
def notifications_api(request):
    return panel_json(notifications_data(request))
