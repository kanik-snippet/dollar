from django.urls import path

from . import mobile_ops, panel_resources, panel_views, subadmin_views, views


app_name = "control"
urlpatterns = [
    path("", views.home, name="home"),
    path("panel/", panel_views.panel, name="panel"),
    path("panel/mobile-ops/", mobile_ops.mobile_ops_page, name="mobile-ops"),
    path("panel/api/mobile-ops/", mobile_ops.mobile_ops_api, name="mobile-ops-api"),
    path(
        "panel/office-ip-whitelist/",
        panel_views.panel_office_ip_whitelist,
        name="panel-office-ip-whitelist",
    ),
    path(
        "panel/api/office-ip-whitelist/",
        panel_views.panel_office_ip_whitelist_api,
        name="panel-office-ip-whitelist-api",
    ),
    path("panel/office-audit/", panel_views.panel_office_audit, name="panel-office-audit"),
    path("subadmin/login/", subadmin_views.subadmin_login, name="subadmin-login"),
    path("subadmin/", subadmin_views.subadmin_dashboard, name="subadmin-dashboard"),
    path("subadmin/domains/", subadmin_views.subadmin_domain_activity, name="subadmin-domains"),
    path("subadmin/suspicious/", subadmin_views.subadmin_suspicious_activity, name="subadmin-suspicious"),
    path("subadmin/devices/", subadmin_views.subadmin_devices, name="subadmin-devices"),
    path("subadmin/ip-access/", subadmin_views.subadmin_ip_access, name="subadmin-ip-access"),
    path("subadmin/logout/", subadmin_views.subadmin_logout, name="subadmin-logout"),
    path("panel/api/devices/", panel_views.panel_devices_api, name="panel-devices-api"),
    path("panel/api/subadmins/", panel_views.panel_subadmins_api, name="panel-subadmins-api"),
    path(
        "panel/api/overview/",
        panel_views.panel_overview_api,
        name="panel-overview-api",
    ),
    path(
        "panel/api/suspicious-activity/",
        panel_views.panel_suspicious_activity_api,
        name="panel-suspicious-activity-api",
    ),
    path(
        "panel/api/domain-activity/",
        panel_views.panel_domain_activity_api,
        name="panel-domain-activity-api",
    ),
    path(
        "panel/api/domain-activity/export/",
        panel_views.panel_domain_activity_export,
        name="panel-domain-activity-export",
    ),
    path(
        "panel/api/domain-activity/<int:activity_id>/",
        panel_views.panel_domain_activity_detail_api,
        name="panel-domain-activity-detail-api",
    ),
    path(
        "panel/api/resources/<str:resource>/",
        panel_resources.panel_resource_api,
        name="panel-resource-api",
    ),
    path("docs/", views.swagger_docs, name="swagger-docs"),
    path("openapi.json", views.openapi_schema, name="openapi-schema"),
    path("healthz/", views.healthz, name="healthz"),
    path("api/v1/ip/", views.public_ipv4, name="public-ipv4"),
    path("api/v1/ys-bridge/poll/", mobile_ops.bridge_poll, name="ys-bridge-poll"),
    path(
        "api/v1/ys-bridge/commands/<uuid:command_id>/complete/",
        mobile_ops.bridge_complete,
        name="ys-bridge-complete",
    ),
    path("api/v1/bootstrap/", views.bootstrap, name="bootstrap"),
    path("api/v1/proxy-jobs/", views.create_proxy_job, name="proxy-job-create"),
    path("api/v1/proxy-jobs/<int:job_id>/", views.proxy_job_detail, name="proxy-job-detail"),
    path(
        "api/v1/proxy-exit-claims/",
        views.proxy_exit_ip_claim,
        name="proxy-exit-ip-claim",
    ),
    path(
        "api/v1/proxy-cities/<str:provider_code>/<str:country_code>/",
        views.proxy_cities,
        name="proxy-cities-country",
    ),
    path(
        "api/v1/proxy-cities/<str:provider_code>/<str:country_code>/<str:region_code>/",
        views.proxy_cities,
        name="proxy-cities",
    ),
    path("api/v1/profile-leases/", views.acquire_profile_lease, name="profile-lease-acquire"),
    path("api/v1/profile-leases/release/", views.release_profile_lease, name="profile-lease-release"),
    path("api/v1/profile-activity/", views.profile_activity, name="profile-activity"),
    path("api/v1/profile-domains/", views.profile_domains, name="profile-domains"),
    path("api/v1/extensions/<int:package_id>/", views.extension_package, name="extension-package"),
    path(
        "api/v1/desktop-releases/<int:release_id>/",
        views.desktop_release_download,
        name="desktop-release-download",
    ),
    path(
        "api/v1/desktop-components/",
        views.desktop_component_manifest,
        name="desktop-component-manifest",
    ),
    path(
        "api/v1/desktop-components/<int:release_id>/",
        views.desktop_component_download,
        name="desktop-component-download",
    ),
    path(
        "api/v1/proxies/<str:provider_code>/<str:country_code>/",
        views.proxy_file,
        name="proxy-file",
    ),
]
