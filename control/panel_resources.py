from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Callable

from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.db import IntegrityError, transaction
from django.views.decorators.http import require_http_methods

from .models import (
    BootstrapAudit,
    BrowserGroupMapping,
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    ExtensionPackage,
    ProfileActivity,
    Provider,
    ProxyCountryFile,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyReservation,
)
from .cache_utils import (
    access_audit_cache_ttl,
    access_audit_cache_version,
    safe_cache_get,
    safe_cache_set,
)
from .panel_views import (
    _panel_datetime_bound,
    admin_change,
    bounded_int,
    iso,
    panel_json,
    profile_display_name,
)
from .tasks import queue_refill_proxy_pool
from .tasks import provider_is_configured
from .geo_catalog import country_rows


def _column(key: str, label: str, kind: str = "text") -> dict[str, str]:
    return {"key": key, "label": label, "type": kind}


def _resource_page(
    request: HttpRequest,
    queryset,
    serializer: Callable[[Any], dict[str, Any]],
    *,
    title: str,
    description: str,
    columns: list[dict[str, str]],
    admin_url: str,
    extra: dict[str, Any] | None = None,
    cache_key: str = "",
    cache_timeout: int | None = None,
) -> JsonResponse:
    if cache_key:
        cached = safe_cache_get(cache_key)
        if isinstance(cached, dict):
            response = panel_json(cached)
            response["X-Panel-Cache"] = "HIT"
            return response
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    payload = {
            "title": title,
            "description": description,
            "columns": columns + [_column("admin_url", "", "action")],
            "rows": [serializer(row) for row in page.object_list],
            "admin_url": admin_url,
            "pagination": {
                "page": page.number,
                "pages": paginator.num_pages,
                "page_size": page_size,
                "total": paginator.count,
                "has_previous": page.has_previous(),
                "has_next": page.has_next(),
            },
        }
    if extra:
        payload.update(extra)
    if cache_key:
        safe_cache_set(cache_key, payload, timeout=cache_timeout)
    response = panel_json(payload)
    if cache_key:
        response["X-Panel-Cache"] = "MISS"
    return response


def _grant_access_from_audit(body: dict[str, Any]) -> JsonResponse:
    try:
        audit = BootstrapAudit.objects.select_related("client").get(
            pk=int(body.get("audit_id"))
        )
    except (BootstrapAudit.DoesNotExist, TypeError, ValueError):
        return panel_json(
            {"ok": False, "message": "Audit record not found."}, status=404
        )

    evidence_ips = {
        str(value)
        for value in (audit.reported_ip, audit.observed_ip)
        if value
    }
    try:
        selected_ip = str(
            ipaddress.IPv4Address(str(body.get("ipv4") or "").strip())
        )
    except ipaddress.AddressValueError:
        return panel_json(
            {"ok": False, "message": "Choose a valid audit IPv4 address."},
            status=400,
        )
    if selected_ip not in evidence_ips:
        return panel_json(
            {"ok": False, "message": "The IPv4 must come from this audit record."},
            status=400,
        )

    client = audit.client
    if client is None and audit.device_id:
        client = (
            ClientAccess.objects.filter(device_id=audit.device_id)
            .order_by("-active", "pk")
            .first()
        )

    created = False
    if client is None:
        device_id = str(audit.device_id or "").strip()
        name = str(body.get("name") or "").strip()[:120]
        office = str(body.get("office") or "").strip()[:64]
        system = str(body.get("system_number") or "").strip()[:32]
        profile_name = str(body.get("profile_name") or name).strip()[:160]
        try:
            config = ConfigBundle.objects.get(
                pk=int(body.get("config_bundle_id")), active=True
            )
        except (ConfigBundle.DoesNotExist, TypeError, ValueError):
            return panel_json(
                {"ok": False, "message": "Choose an active configuration bundle."},
                status=400,
            )
        if not device_id or not name or not office or not system:
            return panel_json(
                {
                    "ok": False,
                    "message": (
                        "Device name, office and system number are required."
                    ),
                },
                status=400,
            )
        try:
            with transaction.atomic():
                client = ClientAccess.objects.create(
                    name=name,
                    ipv4=selected_ip,
                    device_id=device_id,
                    active=True,
                    office_name=office,
                    system_number=system,
                    profile_name=profile_name,
                    config_bundle=config,
                    notes=f"Created from bootstrap audit #{audit.pk}",
                )
                created = True
        except IntegrityError:
            return panel_json(
                {
                    "ok": False,
                    "message": (
                        "This device/IP access entry already exists; refresh "
                        "the page and update the existing device."
                    ),
                },
                status=409,
            )
    else:
        client.active = True
        client.save(update_fields=("active", "updated_at"))
        if str(client.ipv4) != selected_ip:
            allowed_ip, _ = ClientAccessIP.objects.get_or_create(
                client=client,
                ipv4=selected_ip,
                defaults={"active": True},
            )
            if not allowed_ip.active:
                allowed_ip.active = True
                allowed_ip.save(update_fields=("active",))

    if audit.client_id != client.pk:
        audit.client = client
        audit.save(update_fields=("client",))
    verb = "created" if created else "updated"
    return panel_json(
        {
            "ok": True,
            "message": f"{client.name} access {verb}; {selected_ip} is allowed.",
            "client_id": client.pk,
        }
    )


def _generate_office_proxy_pools(body: dict[str, Any]) -> JsonResponse:
    office = str(body.get("office") or "").strip()
    provider = str(body.get("provider") or "P1").strip().upper()
    country = str(body.get("country") or "").strip().upper()
    try:
        target_count = int(body.get("target_count") or 1000)
    except (TypeError, ValueError):
        target_count = 0
    valid_countries = {code for code, _name in country_rows()}
    if not office:
        return panel_json(
            {"ok": False, "message": "Choose an office."}, status=400
        )
    if provider not in {"P1", "P2", "P3"}:
        return panel_json(
            {"ok": False, "message": "Choose P1, P2 or P3."}, status=400
        )
    if country not in valid_countries:
        return panel_json(
            {"ok": False, "message": "Choose a valid country."}, status=400
        )
    if not 1 <= target_count <= 5000:
        return panel_json(
            {"ok": False, "message": "Target stock must be between 1 and 5000."},
            status=400,
        )

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
        return panel_json(
            {
                "ok": False,
                "message": f"No active configuration bundles are assigned to {office}.",
            },
            status=404,
        )

    queued = ready = pending = created = 0
    missing_credentials: list[str] = []
    threshold = min(200, max(1, target_count // 5))
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
        if was_created:
            created += 1
        updates = []
        if target.target_count != target_count:
            target.target_count = target_count
            updates.append("target_count")
        if target.replenish_below != threshold:
            target.replenish_below = threshold
            updates.append("replenish_below")
        if not target.active:
            target.active = True
            updates.append("active")
        if updates:
            updates.append("updated_at")
            target.save(update_fields=updates)
        available = target.entries.filter(state="available").count()
        if available >= target_count:
            ready += 1
        elif queue_refill_proxy_pool(target.pk):
            queued += 1
        else:
            pending += 1

    message = (
        f"{provider} {country} requested for {office}: "
        f"{len(bundles)} bundle(s), {queued} queued, {ready} already ready, "
        f"{pending} already pending, {len(missing_credentials)} missing credentials."
    )
    return panel_json(
        {
            "ok": True,
            "message": message,
            "result": {
                "office": office,
                "provider": provider,
                "country": country,
                "target_count": target_count,
                "bundles_found": len(bundles),
                "targets_created": created,
                "queued": queued,
                "already_ready": ready,
                "already_pending": pending,
                "missing_credentials": missing_credentials,
            },
        }
    )


@staff_member_required(login_url="admin:login")
@require_http_methods(["GET", "POST"])
def panel_resource_api(request: HttpRequest, resource: str) -> JsonResponse:
    if resource == "access-audit" and request.method == "POST":
        try:
            body = json.loads(request.body or "{}")
        except (TypeError, ValueError):
            return panel_json(
                {"ok": False, "message": "Invalid JSON body."}, status=400
            )
        if (
            not isinstance(body, dict)
            or str(body.get("action") or "") != "grant_access"
        ):
            return panel_json(
                {"ok": False, "message": "Unknown access-audit action."},
                status=400,
            )
        return _grant_access_from_audit(body)

    if resource == "proxy-pools" and request.method == "POST":
        try:
            body = json.loads(request.body or "{}")
        except (TypeError, ValueError):
            return panel_json({"ok": False, "message": "Invalid JSON body."}, status=400)
        if not isinstance(body, dict):
            return panel_json({"ok": False, "message": "JSON body must be an object."}, status=400)

        action = str(body.get("action") or "").strip().lower()
        if action == "generate_office":
            if not request.user.is_superuser:
                return panel_json(
                    {"ok": False, "message": "Super-admin access is required."},
                    status=403,
                )
            return _generate_office_proxy_pools(body)
        try:
            target_id = int(body.get("target_id"))
        except (TypeError, ValueError):
            return panel_json({"ok": False, "message": "A valid pool target is required."}, status=400)

        if action not in {"refill", "pause", "resume", "clear"}:
            return panel_json({"ok": False, "message": "Unknown proxy pool action."}, status=400)

        try:
            with transaction.atomic():
                target = ProxyPoolTarget.objects.select_for_update().get(pk=target_id)
                if action == "clear":
                    # Clear only unreserved inventory. Reserved proxies remain
                    # auditable and are never invalidated by this panel action.
                    deleted, _ = target.entries.filter(state="available").delete()
                    target.active = False
                    target.refill_pending = False
                    target.save(update_fields=("active", "refill_pending", "updated_at"))
                    message = f"Cleared {deleted} available proxy entries and paused this pool."
                elif action == "pause":
                    target.active = False
                    target.save(update_fields=("active", "updated_at"))
                    message = "Proxy pool paused. Existing reservations were kept."
                elif action == "resume":
                    target.active = True
                    target.save(update_fields=("active", "updated_at"))
                    message = "Proxy pool resumed."
                else:
                    if not target.active:
                        return panel_json({"ok": False, "message": "Resume this pool before refilling it."}, status=400)
                    message = "Refill queued if this target was not already pending."
        except ProxyPoolTarget.DoesNotExist:
            return panel_json({"ok": False, "message": "Proxy pool target not found."}, status=404)

        if action in {"refill", "resume"}:
            try:
                queue_refill_proxy_pool(target_id)
            except Exception as exc:
                return panel_json({"ok": False, "message": f"Could not queue refill: {exc}"}, status=500)
        return panel_json({"ok": True, "message": message})

    query = str(request.GET.get("q") or "").strip()
    t = lambda key, label: _column(key, label)
    d = lambda key, label: _column(key, label, "date")
    s = lambda key, label: _column(key, label, "status")

    if resource == "devices":
        queryset = ClientAccess.objects.select_related("config_bundle")
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(ipv4__icontains=query)
                | Q(device_id__icontains=query)
                | Q(office_name__icontains=query)
                | Q(profile_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("office_name", "system_number"),
            lambda row: {
                "name": row.name,
                "office": row.office_name,
                "system": row.system_number,
                "ipv4": str(row.ipv4),
                "device_id": row.device_id,
                "profile_name": profile_display_name(row),
                "config": row.config_bundle.name,
                "active": row.active,
                "last_seen": iso(row.last_seen_at),
                "admin_url": admin_change("clientaccess", row.pk),
            },
            title="Devices",
            description="Whitelisted systems, identity, office and profile assignments.",
            columns=[
                t("name", "Device"), t("office", "Office"), t("system", "System"),
                t("ipv4", "Public IP"), t("device_id", "Device ID"),
                t("profile_name", "Profile name"), t("config", "Config"),
                s("active", "Active"), d("last_seen", "Last seen"),
            ],
            admin_url=reverse("admin:control_clientaccess_changelist"),
        )

    if resource == "configurations":
        queryset = ConfigBundle.objects.annotate(client_count=Count("clients"))
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(browser_group_name__icontains=query)
                | Q(browser_group_id__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("name"),
            lambda row: {
                "name": row.name,
                "version": row.version,
                "group_name": row.browser_group_name,
                "group_id": row.browser_group_id or "Testing fallback",
                "clients": row.client_count,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("configbundle", row.pk),
            },
            title="Configuration bundles",
            description="Encrypted settings and fixed office group assignments.",
            columns=[
                t("name", "Bundle"), t("version", "Version"),
                t("group_name", "Group"), t("group_id", "Group ID"),
                t("clients", "Devices"), s("active", "Active"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_configbundle_changelist"),
        )

    if resource == "groups":
        queryset = BrowserGroupMapping.objects.select_related("client")
        if query:
            queryset = queryset.filter(
                Q(internal_name__icontains=query)
                | Q(browser_group_name__icontains=query)
                | Q(browser_group_id__icontains=query)
                | Q(client__name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "internal_name": row.internal_name,
                "browser_name": row.browser_group_name,
                "group_id": row.browser_group_id,
                "client": row.client.name,
                "office": row.client.office_name,
                "default": row.is_default,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("browsergroupmapping", row.pk),
            },
            title="Browser groups",
            description="Known group IDs and internal office labels.",
            columns=[
                t("internal_name", "Internal label"),
                t("browser_name", "Browser group"), t("group_id", "Group ID"),
                t("client", "Device"), t("office", "Office"),
                s("default", "Default"), s("active", "Active"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_browsergroupmapping_changelist"),
        )

    if resource == "providers":
        queryset = Provider.objects.annotate(
            country_count=Count("country_files")
        ).order_by("display_order", "code")
        if query:
            queryset = queryset.filter(
                Q(code__icontains=query) | Q(display_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "code": row.code,
                "name": row.display_name,
                "countries": row.country_count,
                "order": row.display_order,
                "active": row.active,
                "admin_url": admin_change("provider", row.pk),
            },
            title="Providers",
            description="Visible provider codes and uploaded country coverage.",
            columns=[
                t("code", "Code"), t("name", "Display name"),
                t("countries", "Countries"), t("order", "Order"),
                s("active", "Active"),
            ],
            admin_url=reverse("admin:control_provider_changelist"),
        )

    if resource == "proxy-catalog":
        queryset = ProxyCountryFile.objects.select_related("provider")
        if query:
            queryset = queryset.filter(
                Q(provider__code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(country_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "provider": row.provider.code,
                "country": row.country_name,
                "country_code": row.country_code,
                "version": row.version,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("proxycountryfile", row.pk),
            },
            title="Proxy catalog",
            description="Encrypted country TXT inventories available to clients.",
            columns=[
                t("provider", "Provider"), t("country", "Country"),
                t("country_code", "Code"), t("version", "Version"),
                s("active", "Active"), d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_proxycountryfile_changelist"),
        )

    if resource == "extensions":
        queryset = ExtensionPackage.objects.all()
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(filename__icontains=query)
                | Q(package_sha256__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "name": row.name,
                "filename": row.filename,
                "version": row.version,
                "active": row.active,
                "status": row.status,
                "top": row.is_top,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("extensionpackage", row.pk),
            },
            title="Extensions",
            description="Managed extension ZIPs delivered to authorized clients.",
            columns=[
                t("name", "Extension"), t("filename", "Package"),
                t("version", "Version"), s("active", "Active"),
                s("status", "Enabled"), s("top", "Priority"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_extensionpackage_changelist"),
        )

    if resource == "proxy-pools":
        # Keep the expensive entry aggregates out of the unfiltered count query.
        # This page can contain hundreds of thousands of targets, so annotating
        # the complete queryset before Paginator.count() caused every refresh to
        # scan the entry table.  Build a cheap target queryset first, then add
        # counts only to the small page that is rendered below.
        queryset = ProxyPoolTarget.objects.select_related("config_bundle")
        bundle = str(request.GET.get("bundle") or "").strip()
        provider = str(request.GET.get("provider") or "").strip().upper()
        country = str(request.GET.get("country") or "").strip().upper()
        status = str(request.GET.get("status") or "").strip().lower()
        if query:
            queryset = queryset.filter(
                Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(region__icontains=query)
                | Q(city__icontains=query)
                | Q(config_bundle__name__icontains=query)
            )
        if bundle:
            queryset = queryset.filter(config_bundle_id=bundle)
        if provider:
            queryset = queryset.filter(provider_code=provider)
        if country:
            queryset = queryset.filter(country_code=country)
        # Stock filters still need an aggregate, but are deliberately handled
        # after the cheap identity filters above.  The normal (unfiltered) page
        # no longer performs this join for the whole table.
        if status in {"empty", "low", "ready"}:
            queryset = queryset.annotate(
                available_count=Count("entries", filter=Q(entries__state="available")),
            )
            if status == "empty":
                queryset = queryset.filter(available_count=0)
            elif status == "low":
                queryset = queryset.filter(available_count__lte=200)
            else:
                queryset = queryset.filter(available_count__gt=200)

        # These option lists change rarely, while the panel can be refreshed
        # repeatedly during operations.  Cache them briefly so every refresh
        # does not run three DISTINCT scans over the large target table.
        option_cache_key = "panel:proxy-pool-options:v2"
        options = safe_cache_get(option_cache_key)
        if options is None:
            options = {
                "bundles": list(
                    ConfigBundle.objects.filter(active=True, clients__active=True)
                    .distinct()
                    .order_by("name")
                    .values("id", "name", "browser_group_name", "browser_group_id")
                ),
                "providers": list(
                    ProxyPoolTarget.objects.filter(active=True)
                    .values_list("provider_code", flat=True)
                    .distinct()
                    .order_by("provider_code")
                ),
                "countries": list(
                    ProxyPoolTarget.objects.filter(active=True)
                    .values_list("country_code", flat=True)
                    .distinct()
                    .order_by("country_code")
                ),
                "generation_offices": list(
                    ClientAccess.objects.filter(active=True)
                    .exclude(office_name="")
                    .order_by("office_name")
                    .values_list("office_name", flat=True)
                    .distinct()
                ),
                "generation_countries": [
                    {"code": code, "name": name}
                    for code, name in country_rows()
                ],
                "generation_providers": ["P1", "P2", "P3"],
            }
            safe_cache_set(option_cache_key, options, 60)
        bundle_options = options["bundles"]
        provider_options = options["providers"]
        country_options = options["countries"]
        columns = [
            t("provider", "Provider"), t("country", "Country"),
            t("location", "Location"), t("config", "Bundle"),
            t("group_name", "Group"), t("group_id", "Group ID"),
            t("target", "Target"), t("threshold", "Refill below"),
            t("available", "Available"), t("reserved", "Reserved"),
            s("active", "Active"),
        ]
        serializer = lambda row: {
                "target_id": row.pk,
                "provider": row.provider_code,
                "country": row.country_code,
                "location": " / ".join(
                    value for value in (row.region, row.city) if value
                ) or "Any",
                "config": row.config_bundle.name,
                "group_name": row.config_bundle.browser_group_name,
                "group_id": row.config_bundle.browser_group_id,
                "target": row.target_count,
                "threshold": row.replenish_below,
                "available": getattr(row, "available_count", 0),
                "reserved": getattr(row, "reserved_count", 0),
                "active": row.active,
                "refill_pending": row.refill_pending,
                "admin_url": admin_change("proxypooltarget", row.pk),
            }
        page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
        page_number = bounded_int(request.GET.get("page"), 1, 1, 1000000)
        offset = (page_number - 1) * page_size
        # Fetch one extra row instead of running Paginator.count() over an
        # annotated join.  This keeps first paint fast and still gives the UI a
        # reliable Next button.  Counts are added only for the visible rows.
        page_queryset = queryset.annotate(
            available_count=Count("entries", filter=Q(entries__state="available")),
            reserved_count=Count("entries", filter=Q(entries__state="reserved")),
        # Primary-key ordering avoids a filesort across the entire target table
        # (ordering by config_bundle__name was the remaining slow first-load
        # query when the database contains hundreds of thousands of targets).
        ).order_by("pk")
        page_rows = list(page_queryset[offset:offset + page_size + 1])
        has_next = len(page_rows) > page_size
        rows = page_rows[:page_size]
        # Deliberately avoid a full-table COUNT on every refresh.  The UI can
        # navigate using has_next/has_previous, while filters narrow the list
        # without blocking the first render on a remote MySQL connection.
        page_total = None
        return panel_json({
            "kind": "proxy-pools",
            "title": "Proxy pool manager",
            "description": "Track every group/provider/country pool and control refill or clearing without terminal commands.",
            "columns": columns,
            "rows": [serializer(row) for row in rows],
            "admin_url": reverse("admin:control_proxypooltarget_changelist"),
            # Metrics intentionally describe the visible page.  Global stock
            # aggregates are available through filters and no longer block the
            # panel on a full-table scan.
            "metrics": {
                "total": page_total if page_total is not None else len(rows),
                "low": sum(1 for row in rows if int(getattr(row, "available_count", 0)) <= 200),
                "empty": sum(1 for row in rows if int(getattr(row, "available_count", 0)) == 0),
                "available": sum(int(getattr(row, "available_count", 0)) for row in rows),
                "scope": "matching targets on this page" if page_total is None else "matching targets",
            },
            "filters": {
                "q": query, "bundle": bundle, "provider": provider,
                "country": country, "status": status,
            },
            "options": {
                "bundles": bundle_options,
                "providers": provider_options,
                "countries": country_options,
                "generation_offices": options["generation_offices"],
                "generation_countries": options["generation_countries"],
                "generation_providers": options["generation_providers"],
            },
            "pagination": {
                "page": page_number,
                "pages": ((page_total + page_size - 1) // page_size) if page_total is not None else None,
                "page_size": page_size,
                "total": page_total,
                "has_previous": page_number > 1,
                "has_next": has_next,
            },
        })

    if resource == "proxy-inventory":
        queryset = ProxyPoolEntry.objects.select_related("target", "reserved_client")
        if query:
            queryset = queryset.filter(
                Q(target__provider_code__icontains=query)
                | Q(target__country_code__icontains=query)
                | Q(exit_ip__icontains=query)
                | Q(reserved_client__name__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "provider": row.target.provider_code,
                "country": row.target.country_code,
                "state": row.state,
                "exit_ip": str(row.exit_ip or ""),
                "score": row.fraud_score if row.fraud_score is not None else "",
                "device": row.reserved_client.name if row.reserved_client else "",
                "tested_at": iso(row.tested_at),
                "reserved_at": iso(row.reserved_at),
                "admin_url": admin_change("proxypoolentry", row.pk),
            },
            title="Proxy inventory",
            description="Pool state, exit IP quality and reservation ownership.",
            columns=[
                t("provider", "Provider"), t("country", "Country"),
                s("state", "State"), t("exit_ip", "Exit IP"),
                t("score", "Score"), t("device", "Reserved device"),
                d("tested_at", "Tested"), d("reserved_at", "Reserved"),
            ],
            admin_url=reverse("admin:control_proxypoolentry_changelist"),
        )

    if resource == "proxy-jobs":
        queryset = ProxyGenerationJob.objects.select_related("client")
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(status__icontains=query)
                | Q(error__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "id": row.pk,
                "device": row.client.name,
                "provider": row.provider_code,
                "country": row.country_code,
                "location": " / ".join(
                    value for value in (row.region, row.city) if value
                ) or "Any",
                "submitted_count": getattr(row, "submitted_count", row.requested_count),
                "progress": (
                    f"{row.ready_count} / "
                    f"{max(row.requested_count, row.candidate_count)}"
                ),
                "status": row.status,
                "error": row.error,
                "created_at": iso(row.created_at),
                "admin_url": admin_change("proxygenerationjob", row.pk),
            },
            title="Proxy generation jobs",
            description="Requested counts, progress and generation failures.",
            columns=[
                t("id", "Job"), t("device", "Device"),
                t("provider", "Provider"), t("country", "Country"),
                t("submitted_count", "Submitted"),
                t("location", "Location"), t("progress", "Ready"),
                s("status", "Status"), t("error", "Error"),
                d("created_at", "Created"),
            ],
            admin_url=reverse("admin:control_proxygenerationjob_changelist"),
        )

    if resource == "reservations":
        queryset = ProxyReservation.objects.select_related("client", "job")
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(profile_name__icontains=query)
                | Q(profile_id__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-reserved_at"),
            lambda row: {
                "id": row.pk,
                "device": row.client.name,
                "job": row.job_id or "",
                "provider": row.provider_code,
                "country": row.country_code,
                "profile_name": profile_display_name(row),
                "profile_id": row.profile_id,
                "reserved_at": iso(row.reserved_at),
                "admin_url": admin_change("proxyreservation", row.pk),
            },
            title="Proxy reservations",
            description="Unique proxy assignments linked to profile creation.",
            columns=[
                t("id", "Reservation"), t("device", "Device"),
                t("job", "Job"), t("provider", "Provider"),
                t("country", "Country"), t("profile_name", "Profile"),
                t("profile_id", "Profile ID"), d("reserved_at", "Reserved"),
            ],
            admin_url=reverse("admin:control_proxyreservation_changelist"),
        )

    if resource == "profile-activity":
        queryset = ProfileActivity.objects.select_related(
            "client", "job", "reservation"
        )
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(client__device_id__icontains=query)
                | Q(profile_name__icontains=query)
                | Q(profile_id__icontains=query)
                | Q(group_id__icontains=query)
                | Q(status__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "created_at": iso(row.created_at),
                "device": row.client.name,
                "office": row.client.office_name,
                "group_id": row.group_id,
                "profile_name": profile_display_name(row),
                "profile_id": row.profile_id,
                "status": row.status,
                "job": row.job_id or "",
                "reservation": row.reservation_id or "",
                "admin_url": admin_change("profileactivity", row.pk),
            },
            title="Profile activity",
            description="Profile request, reservation and open lifecycle events.",
            columns=[
                d("created_at", "Time"), t("device", "Device"),
                t("office", "Office"), t("group_id", "Group"),
                t("profile_name", "Profile"), t("profile_id", "Profile ID"),
                s("status", "Status"), t("job", "Job"),
                t("reservation", "Reservation"),
            ],
            admin_url=reverse("admin:control_profileactivity_changelist"),
        )

    if resource == "access-audit":
        queryset = BootstrapAudit.objects.select_related("client")
        if query:
            try:
                exact_ip = str(ipaddress.IPv4Address(query))
            except ipaddress.AddressValueError:
                exact_ip = ""
            if exact_ip:
                queryset = queryset.filter(
                    Q(observed_ip=exact_ip) | Q(reported_ip=exact_ip)
                )
            elif len(query) >= 32 and " " not in query:
                queryset = queryset.filter(device_id=query)
            else:
                queryset = queryset.filter(
                    Q(device_id__icontains=query)
                    | Q(client__name__icontains=query)
                    | Q(reason__icontains=query)
                )
        allowed = str(request.GET.get("allowed") or "").strip().lower()
        if allowed in {"1", "0"}:
            queryset = queryset.filter(allowed=allowed == "1")
        start = _panel_datetime_bound(request.GET.get("from"))
        end = _panel_datetime_bound(request.GET.get("to"))
        if start:
            queryset = queryset.filter(created_at__gte=start)
        if end:
            queryset = queryset.filter(created_at__lte=end)
        try:
            cursor = max(0, int(request.GET.get("cursor") or 0))
        except (TypeError, ValueError):
            cursor = 0
        if cursor:
            queryset = queryset.filter(pk__lt=cursor)

        page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
        version = access_audit_cache_version()
        signature = hashlib.sha256(
            request.GET.urlencode().encode("utf-8")
        ).hexdigest()[:24]
        audit_cache_key = f"panel:access-audit:v{version}:{signature}"
        cached = safe_cache_get(audit_cache_key)
        if isinstance(cached, dict):
            response = panel_json(cached)
            response["X-Panel-Cache"] = "HIT"
            return response

        records = list(queryset.order_by("-pk")[: page_size + 1])
        has_next = len(records) > page_size
        records = records[:page_size]
        rows = [
            {
                "id": row.pk,
                "created_at": iso(row.created_at),
                "client": row.client.name if row.client else "Unknown",
                "client_id": row.client_id or "",
                "observed_ip": str(row.observed_ip or ""),
                "reported_ip": str(row.reported_ip or ""),
                "device_id": row.device_id,
                "allowed": row.allowed,
                "reason": row.reason,
                "version": row.app_version,
                "can_grant": bool(
                    row.device_id and (row.observed_ip or row.reported_ip)
                ),
                "admin_url": admin_change("bootstrapaudit", row.pk),
            }
            for row in records
        ]
        configurations = list(
            ConfigBundle.objects.filter(active=True)
            .order_by("name")
            .values("id", "name", "browser_group_name", "browser_group_id")
        )
        payload = {
            "title": "Access audit",
            "description": "Bootstrap authorization decisions with IP and device evidence.",
            "rows": rows,
            "columns": [
                d("created_at", "Time"),
                t("client", "Client"),
                t("observed_ip", "Observed IP"),
                t("reported_ip", "Reported IP"),
                t("device_id", "Device ID"),
                s("allowed", "Allowed"),
                t("reason", "Reason"),
                t("version", "App version"),
            ],
            "configurations": configurations,
            "admin_url": reverse("admin:control_bootstrapaudit_changelist"),
            "filters": {
                "q": query,
                "allowed": allowed,
                "from": str(request.GET.get("from") or ""),
                "to": str(request.GET.get("to") or ""),
            },
            "pagination": {
                "page_size": page_size,
                "has_previous": bool(cursor),
                "has_next": has_next,
                "next_cursor": records[-1].pk if has_next and records else "",
                "total": None,
            },
        }
        safe_cache_set(
            audit_cache_key,
            payload,
            timeout=access_audit_cache_ttl(audit_cache_key),
        )
        response = panel_json(payload)
        response["X-Panel-Cache"] = "MISS"
        return response

    return panel_json({"message": "Unknown panel resource."}, status=404)
