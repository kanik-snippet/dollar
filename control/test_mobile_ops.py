import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import (
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    ProxyPoolTarget,
    YSBridgeAgent,
    YSBridgeCommand,
)


class MobileOpsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="mobile-admin", password="test-password"
        )
        self.client.force_login(self.user)
        self.bundle = ConfigBundle.objects.create(
            name="OFFICE-G1-PC-001",
            browser_group_id="4401",
            browser_group_name="Office group",
        )
        self.bundle.set_payload(
            {"MASSIVE_PROXY_USERNAME": "test-user", "MASSIVE_API_KEY": "test-key"}
        )
        self.bundle.save(update_fields=("payload_ciphertext",))
        self.device_a = ClientAccess.objects.create(
            name="Device A",
            ipv4="198.51.100.10",
            device_id="device-a",
            office_name="Office One",
            system_number="1",
            config_bundle=self.bundle,
        )
        self.device_b = ClientAccess.objects.create(
            name="Device B",
            ipv4="198.51.100.11",
            device_id="device-b",
            office_name="Office One",
            system_number="2",
            config_bundle=self.bundle,
        )
        self.agent_token = "ysb_test-agent-token-with-enough-entropy"
        self.agent = YSBridgeAgent(name="Test office PC")
        self.agent.set_token(self.agent_token)
        self.agent.save()

    def post_mobile(self, payload):
        return self.client.post(
            reverse("control:mobile-ops-api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_mobile_page_and_options_are_staff_protected(self):
        page = self.client.get(reverse("control:mobile-ops"))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Mobile Quick Ops")
        response = self.client.get(reverse("control:mobile-ops-api"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("Office One", response.json()["offices"])
        self.assertNotIn("token_hash", json.dumps(response.json()))

    def test_adds_ipv4_to_every_active_office_device(self):
        response = self.post_mobile(
            {"action": "add_office_ipv4", "office": "Office One", "ipv4": "203.0.113.25"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"]["created"], 2)
        self.assertEqual(
            ClientAccessIP.objects.filter(ipv4="203.0.113.25", active=True).count(), 2
        )

    @patch("control.mobile_ops.refill_proxy_pool.run", return_value=1000)
    def test_generates_proxy_pool_synchronously(self, refill_run):
        response = self.post_mobile(
            {
                "action": "generate_proxies",
                "office": "Office One",
                "provider": "P3",
                "country": "CO",
                "target_count": 1000,
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"]["proxies_generated"], 1000)
        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle, provider_code="P3", country_code="CO"
        )
        refill_run.assert_called_once_with(target.pk)

    def test_delete_command_is_office_scoped_and_completed_by_bridge(self):
        queued = self.post_mobile(
            {
                "action": "queue_ys_delete",
                "office": "Office One",
                "confirmation": "DELETE",
            }
        )
        self.assertEqual(queued.status_code, 200)
        command = YSBridgeCommand.objects.get()
        self.assertEqual(command.payload["group_ids"], ["4401"])

        poll = self.client.post(
            reverse("control:ys-bridge-poll"),
            data="{}",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.agent_token}",
            HTTP_X_BRIDGE_VERSION="test",
        )
        self.assertEqual(poll.status_code, 200)
        self.assertEqual(poll.json()["command"]["id"], str(command.pk))

        complete = self.client.post(
            reverse("control:ys-bridge-complete", args=(command.pk,)),
            data=json.dumps(
                {"success": True, "result": {"matched": 2, "closed": 2, "deleted": 2}}
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.agent_token}",
        )
        self.assertEqual(complete.status_code, 200)
        command.refresh_from_db()
        self.assertEqual(command.status, YSBridgeCommand.STATUS_SUCCEEDED)
        self.assertEqual(command.result["deleted"], 2)

    def test_bridge_rejects_invalid_token(self):
        response = self.client.post(
            reverse("control:ys-bridge-poll"),
            data="{}",
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer wrong-token",
        )
        self.assertEqual(response.status_code, 401)
