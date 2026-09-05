import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import (
    BootstrapAudit,
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    DesktopOfficeAccessPolicy,
    Provider,
    ProxyPoolEntry,
    ProxyPoolTarget,
)


class OperationsPanelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="ops-admin", email="ops@example.com", password="test-pass"
        )
        self.client.force_login(self.user)
        self.bundle = ConfigBundle.objects.create(name="IPLV-PC-01")
        self.bundle.set_payload({"MASSIVE_PROXY_USERNAME": "user", "MASSIVE_API_KEY": "secret"})
        self.bundle.save()
        self.device = ClientAccess.objects.create(
            name="IPLV system 01",
            ipv4="198.51.100.10",
            device_id="device-iplv-01",
            office_name="IPLV",
            system_number="01",
            config_bundle=self.bundle,
        )
        personal_bundle = ConfigBundle.objects.create(name="PERSONAL-TEST")
        self.personal_device = ClientAccess.objects.create(
            name="Personal testing",
            ipv4="198.51.100.20",
            device_id="personal-device",
            office_name="Personal",
            system_number="01",
            config_bundle=personal_bundle,
        )
        Provider.objects.create(code="P3", display_name="P3", active=True)

    def post(self, name, body):
        return self.client.post(
            reverse(name),
            data=json.dumps(body),
            content_type="application/json",
        )

    def test_access_workspace_hides_personal_and_approves_existing_device(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="203.0.113.44",
            reported_ip="203.0.113.44",
            device_id=self.device.device_id,
            allowed=False,
            reason="not-whitelisted",
            app_version="1.6.1",
        )
        response = self.client.get(reverse("control:panel-access-api"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["offices"], ["IPLV"])
        self.assertEqual(payload["unread_count"], 1)

        response = self.post("control:panel-access-api", {
            "action": "approve_request",
            "audit_id": audit.pk,
            "ipv4": "203.0.113.44",
            "scope": "device",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClientAccess.objects.filter(device_id=self.device.device_id).count(), 1)
        self.assertTrue(ClientAccessIP.objects.filter(client=self.device, ipv4="203.0.113.44", active=True).exists())
        audit.refresh_from_db()
        self.assertEqual(audit.review_status, BootstrapAudit.REVIEW_APPROVED)
        self.assertIsNotNone(audit.read_at)

    @patch("control.panel_operations.queue_refill_proxy_pool", return_value=True)
    def test_proxy_workspace_generates_and_removes_scoped_stock(self, queue_refill):
        response = self.post("control:panel-proxy-api", {
            "action": "generate",
            "scope": "device",
            "client_id": self.device.pk,
            "provider": "P3",
            "country": "US",
            "target_count": 100,
            "threshold": 20,
        })
        self.assertEqual(response.status_code, 200)
        target = ProxyPoolTarget.objects.get(config_bundle=self.bundle, provider_code="P3", country_code="US")
        entry = ProxyPoolEntry(target=target, proxy_fingerprint="f" * 64, state="available")
        entry.set_proxy("http://user:pass@example.com:8080")
        entry.save()

        response = self.post("control:panel-proxy-api", {
            "action": "remove_available",
            "scope": "device",
            "client_id": self.device.pk,
            "provider": "P3",
            "country": "US",
            "confirmation": "REMOVE AVAILABLE",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProxyPoolEntry.objects.filter(pk=entry.pk).exists())
        target.refresh_from_db()
        self.assertFalse(target.active)

    def test_optix_policy_override_and_remote_command_are_device_bound(self):
        response = self.post("control:panel-optix-api", {
            "action": "save_office",
            "office": "IPLV",
            "active": True,
            "providers": ["P3"],
            "browsers": ["B1"],
            "devices": ["desktop"],
            "show_logs": False,
            "release_channel": "testing",
            "activation_mode": "inherit",
        })
        self.assertEqual(response.status_code, 200)
        policy = DesktopOfficeAccessPolicy.objects.get(office_name="IPLV")
        self.assertEqual(policy.allowed_provider_codes, ["P3"])

        response = self.post("control:panel-optix-api", {
            "action": "schedule_uninstall",
            "client_id": self.device.pk,
            "confirmation": "01",
        })
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.desktop_remote_action, ClientAccess.REMOTE_ACTION_UNINSTALL)
        self.assertEqual(self.device.desktop_remote_action_revision, 1)
        self.assertEqual(self.device.desktop_remote_action_requested_by, self.user)
        self.assertIsNone(self.device.desktop_remote_action_acknowledged_at)

    def test_dollar_control_includes_personal_installed_devices(self):
        self.personal_device.desktop_client_product = ClientAccess.DESKTOP_PRODUCT_DOLLAR
        self.personal_device.desktop_client_version = "0.2.1"
        self.personal_device.save(update_fields=("desktop_client_product", "desktop_client_version"))

        response = self.client.get(reverse("control:panel-optix-api"), {"office": "Personal"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("Personal", payload["offices"])
        self.assertEqual(payload["office"], "Personal")
        self.assertEqual(len(payload["rows"]), 1)
        self.assertEqual(payload["rows"][0]["product"]["code"], ClientAccess.DESKTOP_PRODUCT_DOLLAR)

    def test_panel_navigation_has_focused_operations_and_releases(self):
        response = self.client.get(reverse("control:panel"))
        self.assertContains(response, 'data-route="access"')
        self.assertContains(response, 'data-route="proxy"')
        self.assertContains(response, 'data-route="optix"')
        self.assertContains(response, 'data-route="releases"')
        self.assertNotContains(response, 'data-route="overview"')
        self.assertNotContains(response, "Domain activity")
