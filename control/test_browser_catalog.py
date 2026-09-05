"""Isolated YS metadata tests. Every upstream request is mocked; no downloads."""
from copy import deepcopy
from datetime import timedelta
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from django.conf import settings
from django.db.models.query import QuerySet
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from . import browser_catalog as catalog
from .models import BrowserCatalogSnapshot


def common_data(**extra):
    data = {
        "osData": {"Windows": [{"label": "Windows 11", "value": "11"}]},
        "winCpuList": [{"cores": 8, "weight": 1}],
        "fontList": [{"id": 1, "name": "Example Sans"}],
        "winScreen": [{"label": "1920x1080", "value": "1920x1080"}],
        "versionsByMajor": {"140": ["140.0.7339.210"]},
    }
    data.update(extra)
    return data


class CommonCatalogValidationTests(SimpleTestCase):
    def test_accepts_objects_and_json_encoded_catalog_values(self):
        expected = common_data()
        encoded = {key: json.dumps(value) for key, value in expected.items()}
        self.assertEqual(catalog.validate_common(encoded), expected)
        self.assertEqual(catalog.validate_common(expected), expected)

    def test_allowlist_drops_credentials_routing_and_secure_json(self):
        source = common_data(
            apiKey="mock-secret", authToken="mock-token", SecureJson={"script": "never-import"},
            ipList=["https://private.invalid/ip"], domainUrlConfig="https://private.invalid/",
            downloadUrl="https://private.invalid/browser.exe", unexpected="drop",
        )
        actual = catalog.validate_common(source)
        self.assertEqual(actual, common_data())
        self.assertTrue(set(actual).issubset(catalog.COMMON_KEYS))
        self.assertNotIn("mock-secret", catalog.canonical(actual))

    def test_every_required_catalog_must_be_present_and_nonempty(self):
        for key in catalog.REQUIRED_KEYS:
            for missing in (True, False):
                with self.subTest(key=key, missing=missing):
                    data = common_data()
                    if missing:
                        del data[key]
                    else:
                        data[key] = {} if key in catalog.OBJECT_KEYS else []
                    with self.assertRaises(catalog.CatalogSyncError):
                        catalog.validate_common(data)

    def test_rejects_invalid_json_top_level_types_and_nonfinite_values(self):
        for replacement in ("not-json", {}, None, [{"id": 1, "name": float("nan")} ]):
            with self.subTest(kind=type(replacement).__name__):
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.validate_common(common_data(fontList=replacement))

    def test_required_catalog_inner_shapes_are_checked(self):
        invalid = [
            common_data(osData={"Windows": "not-an-array"}),
            common_data(osData={"Windows": [], "Android": []}),
            common_data(osData={"Windows": [], "Android": [{"label": "Android 14", "value": "14"}]}),
            common_data(winCpuList=[{"cores": -2, "weight": 1}]),
            common_data(fontList=[{"id": "bad", "name": {"api_key": "mock-secret"}}]),
            common_data(winScreen=[{"label": "bad", "value": {"script": "bad"}}]),
        ]
        for data in invalid:
            with self.subTest(field=next(key for key in data if data[key] != common_data()[key])):
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.validate_common(data)

    def test_rejects_prototype_keys_oversized_strings_and_deep_nesting(self):
        nested = []
        for _ in range(14):
            nested = [nested]
        for extra in ({"__proto__": {}}, {"constructor": {}}, "x" * 8193, nested):
            with self.subTest(kind=type(extra).__name__):
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.validate_common(common_data(font=[extra]))


class BrowserMetadataTests(SimpleTestCase):
    def test_browser_rows_are_discovery_only_and_never_download_instructions(self):
        result = catalog.validate_browser_row({
            "version": 140, "osVersion": "Windows", "browserType": 1,
            "downloadUrl": "https://never-fetch.invalid/140.zip", "apiKey": "mock-key",
            "runtime_target": "desktop", "installable": True, "script": "never-run",
        })
        self.assertEqual(result, {
            "version": "140", "osVersion": "Windows", "browserType": 1,
            "runtime_target": "unverified", "installable": False,
        })

    def test_rejects_bad_version_and_untyped_metadata(self):
        for row in ({"version": "../../run.exe"}, {"version": True}, {"version": 140, "osVersion": []}):
            with self.subTest(row_type=type(row.get("version")).__name__):
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.validate_browser_row(row)

    @patch("control.browser_catalog.upstream_post")
    def test_missing_server_key_does_not_make_browser_request(self, upstream):
        with self.assertRaises(catalog.CatalogSyncError):
            catalog.fetch_browser_versions("")
        upstream.assert_not_called()

    @patch("control.browser_catalog.PAGE_SIZE", 2)
    @patch("control.browser_catalog.upstream_post")
    def test_paginates_complete_catalog_with_bounded_form_fields(self, upstream):
        upstream.side_effect = [
            {"rows": [{"version": 137}, {"version": 138}], "total": 3},
            {"rows": [{"version": 140}], "total": 3},
        ]
        rows = catalog.fetch_browser_versions("mock-server-only-key")
        self.assertEqual([row["version"] for row in rows], ["137", "138", "140"])
        self.assertEqual(upstream.call_count, 2)
        for page, call in enumerate(upstream.call_args_list, 1):
            self.assertEqual(call.args, (
                "/api/aegisVersion/aegisCheck", {"pageNum": page, "pageSize": 2},
                "mock-server-only-key",
            ))
        self.assertTrue(all(row["runtime_target"] == "unverified" and row["installable"] is False for row in rows))

    @patch("control.browser_catalog.PAGE_SIZE", 2)
    @patch("control.browser_catalog.upstream_post")
    def test_rejects_empty_repeated_incomplete_and_changing_pages(self, upstream):
        pair = [{"version": 137}, {"version": 138}]
        cases = [
            [{"rows": [], "total": 0}],
            [{"rows": pair, "total": 4}, {"rows": pair, "total": 4}],
            [{"rows": pair, "total": 3}, {"rows": [], "total": 3}],
            [{"rows": pair, "total": 3}, {"rows": [{"version": 140}], "total": 4}],
        ]
        for pages in cases:
            with self.subTest(pages=len(pages)):
                upstream.side_effect = pages
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.fetch_browser_versions("mock-key")

    @patch("control.browser_catalog.PAGE_SIZE", 2)
    @patch("control.browser_catalog.MAX_PAGES", 2)
    @patch("control.browser_catalog.upstream_post")
    def test_rejects_catalog_exceeding_page_cap(self, upstream):
        upstream.side_effect = [[{"version": 137}, {"version": 138}], [{"version": 139}, {"version": 140}]]
        with self.assertRaises(catalog.CatalogSyncError):
            catalog.fetch_browser_versions("mock-key")
        self.assertEqual(upstream.call_count, 2)

    @patch("control.browser_catalog.PAGE_SIZE", 2)
    @patch("control.browser_catalog.upstream_post")
    def test_rejects_oversized_upstream_page_without_total(self, upstream):
        upstream.side_effect = [[{"version": 137}, {"version": 138}, {"version": 140}], []]
        with self.assertRaises(catalog.CatalogSyncError):
            catalog.fetch_browser_versions("mock-key")


class UpstreamTransportTests(SimpleTestCase):
    @patch("control.browser_catalog.request.build_opener")
    def test_fixed_https_post_common_no_auth_and_browser_server_key(self, build_opener):
        response = Mock()
        response.read.return_value = b'{"code":0,"data":{"ok":true},"msg":"ok"}'
        build_opener.return_value.open.return_value.__enter__.return_value = response
        for key in ("", "mock-upstream-key"):
            result = catalog.upstream_post("/api/common/getWebConfigValue", {"configKey": "fontList"}, key)
            self.assertEqual(result, {"ok": True})
            call = build_opener.return_value.open.call_args
            req = call.args[0]
            self.assertEqual(req.full_url, "https://admin.ysbrowser.com/api/common/getWebConfigValue")
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.data, b"configKey=fontList")
            self.assertEqual(call.kwargs["timeout"], 15)
            headers = {name.lower(): value for name, value in req.header_items()}
            self.assertEqual(headers["content-type"], "application/x-www-form-urlencoded")
            self.assertEqual(headers.get("x-api-key", ""), key)
            self.assertNotIn("authorization", headers)
        response.read.assert_called_with(catalog.MAX_BYTES + 1)
        handlers = build_opener.call_args.args
        self.assertTrue(any(isinstance(handler, catalog.NoRedirect) for handler in handlers))
        self.assertTrue(any(getattr(handler, "proxies", None) == {} for handler in handlers))

    @patch("control.browser_catalog.request.build_opener")
    def test_transport_refuses_bad_key_before_any_network(self, opener):
        for key in ("bad\nInjected: header", "x" * 4097):
            with self.assertRaises(catalog.CatalogSyncError):
                catalog.upstream_post("/api/aegisVersion/aegisCheck", api_key=key)
        opener.assert_not_called()

    def test_redirect_cannot_forward_key_to_another_host(self):
        with self.assertRaises(catalog.CatalogSyncError):
            catalog.NoRedirect().redirect_request(None, None, 302, "", {}, "https://untrusted.invalid/")

    @patch("control.browser_catalog.request.build_opener")
    def test_http_errors_do_not_include_response_or_credential_details(self, opener):
        opener.return_value.open.side_effect = HTTPError("https://private.invalid/mock-key", 403, "mock-secret", {}, None)
        with self.assertRaises(catalog.CatalogSyncError) as caught:
            catalog.upstream_post("/api/aegisVersion/aegisCheck", api_key="mock-key")
        self.assertEqual(str(caught.exception), "YS returned HTTP 403.")

    @patch("control.browser_catalog.request.build_opener")
    def test_rejects_bad_success_envelopes_and_oversized_response(self, opener):
        response = Mock()
        opener.return_value.open.return_value.__enter__.return_value = response
        for body in (b"not-json", b"[]", b'{"code":true,"data":{}}', b'{"code":1,"data":{}}', b'{"data":{}}'):
            response.read.return_value = body
            with self.subTest(body_size=len(body)):
                with self.assertRaises(catalog.CatalogSyncError):
                    catalog.upstream_post("/api/common/getWebConfigValue")
        with patch("control.browser_catalog.MAX_BYTES", 16):
            response.read.return_value = b"x" * 17
            with self.assertRaises(catalog.CatalogSyncError):
                catalog.upstream_post("/api/common/getWebConfigValue")


@override_settings(YS_CATALOG_SYNC_ENABLED=True, YS_UPSTREAM_API_KEY="mock-server-only-key")
class CatalogSnapshotTests(TestCase):
    def seed(self, name="common", payload=None):
        value = common_data() if payload is None else payload
        now = timezone.now() - timedelta(days=1)
        return BrowserCatalogSnapshot.objects.create(
            name=name, payload=value, revision=catalog.digest(value),
            last_success_at=now, data_updated_at=now,
        )

    @patch("control.browser_catalog.upstream_post")
    def test_sync_success_is_allowlisted_and_idempotent(self, upstream):
        def fetched(path, fields=None, api_key=""):
            if path == "/api/common/getWebConfigValue":
                self.assertEqual(api_key, "")
                return common_data(apiKey="drop-secret", ipList=["https://never-fetch.invalid/"])
            self.assertEqual(path, "/api/aegisVersion/aegisCheck")
            return {"rows": [{"version": 140, "downloadUrl": "https://never-download.invalid/file.zip"}], "total": 1}
        upstream.side_effect = fetched
        first = catalog.sync_catalogs()
        self.assertEqual([row["status"] for row in first], ["updated", "updated"])
        payload = catalog.current_catalog()
        self.assertEqual(payload["schema_version"], 1)
        self.assertRegex(payload["revision"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload["catalogs"], common_data())
        self.assertEqual(payload["browser_versions"], [{"version": "140", "runtime_target": "unverified", "installable": False}])
        stamp = BrowserCatalogSnapshot.objects.get(name="common").data_updated_at
        second = catalog.sync_catalogs()
        self.assertEqual([row["status"] for row in second], ["unchanged", "unchanged"])
        self.assertEqual(BrowserCatalogSnapshot.objects.get(name="common").data_updated_at, stamp)
        descriptor = catalog.current_catalog(descriptor=True)
        self.assertEqual(descriptor["download_path"], "/api/v1/browser-catalog/")
        self.assertNotIn("catalogs", descriptor)
        self.assertEqual(descriptor["revision"], payload["revision"])

    def test_invalid_common_retains_last_good_payload_revision_and_timestamp(self):
        row = self.seed()
        before = (deepcopy(row.payload), row.revision, row.last_success_at, row.data_updated_at)
        result = catalog.sync_resource("common", lambda: catalog.validate_common({"fontList": []}))
        self.assertEqual(result["status"], "failed")
        row.refresh_from_db()
        self.assertEqual((row.payload, row.revision, row.last_success_at, row.data_updated_at), before)
        self.assertTrue(row.last_error)
        self.assertEqual(row.lease_token, "")
        self.assertIsNone(row.lease_until)

    @patch("control.browser_catalog.upstream_post", return_value={"rows": [], "total": 0})
    def test_empty_browser_result_retains_last_good(self, upstream):
        row = self.seed("browser_versions", [{"version": "137", "runtime_target": "unverified", "installable": False}])
        before = (deepcopy(row.payload), row.revision)
        result = catalog.sync_resource("browser_versions", lambda: catalog.fetch_browser_versions("mock-key"))
        row.refresh_from_db()
        self.assertEqual(result["status"], "failed")
        self.assertEqual((row.payload, row.revision), before)

    def test_partial_common_update_preserves_known_optional_catalog(self):
        self.seed(payload=common_data(NVIDIA=["preserved renderer"]))
        result = catalog.sync_resource("common", lambda: catalog.validate_common(common_data()))
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(BrowserCatalogSnapshot.objects.get(name="common").payload["NVIDIA"], ["preserved renderer"])

    def test_merged_partial_catalog_must_stay_within_final_size_limit(self):
        previous = common_data(NVIDIA=["a" * 200])
        incoming = common_data(AMD=["b" * 200])
        row = self.seed(payload=previous)
        limit = len(catalog.canonical(previous).encode("utf-8")) + 20
        with patch("control.browser_catalog.MAX_BYTES", limit):
            self.assertEqual(catalog.validate_common(previous), previous)
            self.assertEqual(catalog.validate_common(incoming), incoming)
            result = catalog.sync_resource("common", lambda: catalog.validate_common(incoming))
        self.assertEqual(result["status"], "failed")
        row.refresh_from_db()
        self.assertEqual(row.payload, previous)

    def test_failure_details_are_sanitized(self):
        self.seed()
        fetch = Mock(side_effect=RuntimeError("mock-secret and private response body"))
        result = catalog.sync_resource("common", fetch)
        self.assertNotIn("mock-secret", json.dumps(result))
        self.assertNotIn("mock-secret", BrowserCatalogSnapshot.objects.get(name="common").last_error)

    def test_live_lease_prevents_fetch_and_expired_lease_can_be_reclaimed(self):
        row = self.seed()
        row.lease_token = "other-worker"
        row.lease_until = timezone.now() + timedelta(minutes=5)
        row.save()
        fetch = Mock(return_value=common_data())
        self.assertEqual(catalog.sync_resource("common", fetch)["status"], "busy")
        fetch.assert_not_called()
        row.lease_until = timezone.now() - timedelta(seconds=1)
        row.save()
        self.assertEqual(catalog.sync_resource("common", fetch)["status"], "unchanged")
        fetch.assert_called_once()

    def test_lost_lease_cannot_replace_other_workers_snapshot(self):
        row = self.seed()
        prior = deepcopy(row.payload)
        def losing_fetch():
            BrowserCatalogSnapshot.objects.filter(pk=row.pk).update(lease_token="new-owner")
            return common_data(font=["new font"])
        self.assertEqual(catalog.sync_resource("common", losing_fetch)["status"], "lease_lost")
        row.refresh_from_db()
        self.assertEqual(row.payload, prior)
        self.assertEqual(row.lease_token, "new-owner")

    def test_lease_acquisition_uses_latest_committed_optional_catalog(self):
        row = self.seed(payload=common_data(NVIDIA=["old renderer"]))
        newer = common_data(NVIDIA=["newer renderer"])
        original_update = QuerySet.update
        raced = False
        def intercept(queryset, **kwargs):
            nonlocal raced
            if not raced and "last_attempt_at" in kwargs and kwargs.get("lease_token"):
                raced = True
                original_update(BrowserCatalogSnapshot.objects.filter(pk=row.pk), payload=newer, revision=catalog.digest(newer))
            return original_update(queryset, **kwargs)
        with patch.object(QuerySet, "update", intercept):
            result = catalog.sync_resource("common", lambda: catalog.validate_common(common_data()))
        self.assertTrue(raced)
        self.assertEqual(result["status"], "unchanged")
        row.refresh_from_db()
        self.assertEqual(row.payload["NVIDIA"], ["newer renderer"])

    @override_settings(YS_CATALOG_SYNC_ENABLED=False)
    @patch("control.browser_catalog.upstream_post")
    def test_disabled_schedule_does_not_fetch_or_create_rows(self, upstream):
        self.assertEqual(catalog.sync_catalogs(), [{"status": "disabled"}])
        upstream.assert_not_called()
        self.assertFalse(BrowserCatalogSnapshot.objects.exists())


class CatalogScheduleTests(SimpleTestCase):
    def test_schedule_runs_at_four_fixed_ist_times_on_dedicated_queue(self):
        entries = [entry for entry in settings.CELERY_BEAT_SCHEDULE.values() if entry["task"] == "control.tasks.sync_ys_browser_catalogs"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(settings.TIME_ZONE, "Asia/Kolkata")
        self.assertEqual(settings.CELERY_TIMEZONE, "Asia/Kolkata")
        self.assertEqual(entries[0]["schedule"].hour, {8, 12, 16, 20})
        self.assertEqual(entries[0]["schedule"].minute, {0})
        self.assertEqual(entries[0]["options"]["queue"], "catalog-sync")

    @patch("control.browser_catalog.sync_catalogs", return_value=[{"status": "disabled"}])
    def test_celery_task_delegates_only_to_metadata_sync(self, sync):
        from .tasks import sync_ys_browser_catalogs
        self.assertEqual(sync_ys_browser_catalogs.run(), [{"status": "disabled"}])
        sync.assert_called_once_with()

    @patch("controlserver.celery.app.send_task")
    def test_catalog_only_worker_start_does_not_generate_proxy_jobs(self, send_task):
        from controlserver.celery import prefill_proxy_pools_on_worker_start
        sender = SimpleNamespace(task_consumer=SimpleNamespace(queues=[SimpleNamespace(name="catalog-sync")]))
        prefill_proxy_pools_on_worker_start(sender=sender)
        send_task.assert_not_called()

    @patch("controlserver.celery.app.send_task")
    def test_existing_proxy_worker_start_behavior_is_preserved(self, send_task):
        from controlserver.celery import prefill_proxy_pools_on_worker_start
        sender = SimpleNamespace(task_consumer=SimpleNamespace(queues=[SimpleNamespace(name="proxy-jobs")]))
        prefill_proxy_pools_on_worker_start(sender=sender)
        send_task.assert_called_once_with("control.tasks.maintain_proxy_pools", kwargs={"force": True}, queue="proxy-jobs")


class CatalogEndpointTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_endpoint_rejects_missing_authentication(self):
        from .views import browser_catalog
        response = browser_catalog(self.factory.get("/api/v1/browser-catalog/"))
        self.assertEqual(response.status_code, 403)

    @patch("control.views._authenticated_client", return_value=SimpleNamespace(desktop_client_product="optix"))
    def test_endpoint_rejects_authenticated_non_dollar_client(self, authenticated):
        from .views import browser_catalog
        self.assertEqual(browser_catalog(self.factory.get("/api/v1/browser-catalog/")).status_code, 403)

    @patch("control.views._authenticated_client", return_value=SimpleNamespace(desktop_client_product="dollar"))
    def test_endpoint_returns_503_until_validated_snapshot_exists(self, authenticated):
        from .views import browser_catalog
        self.assertEqual(browser_catalog(self.factory.get("/api/v1/browser-catalog/")).status_code, 503)

    @patch("control.views._authenticated_client", return_value=SimpleNamespace(desktop_client_product="dollar"))
    def test_endpoint_delivers_private_discovery_only_metadata(self, authenticated):
        from .views import browser_catalog
        catalog.sync_resource("common", lambda: catalog.validate_common(common_data()))
        response = browser_catalog(self.factory.get("/api/v1/browser-catalog/"))
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["schema_version"], 1)
        self.assertEqual(body["catalogs"], common_data())
        self.assertEqual(body["browser_versions"], [])
        self.assertRegex(body["revision"], r"^[0-9a-f]{64}$")
        self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
