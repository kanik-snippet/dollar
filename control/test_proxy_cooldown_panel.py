import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.test import Client, TestCase
from django.urls import reverse


POLICY = {"enabled": True, "cooldown_hours": 25, "updated_at": None, "revision": 4}


class ProxyCooldownPanelTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("cooldown-staff", password="test", is_staff=True)
        self.admin = get_user_model().objects.create_superuser("cooldown-admin", "admin@example.test", "test")
        self.url = reverse("control:panel-proxy-cooldown-api")

    def post(self, payload):
        return self.client.post(self.url, json.dumps(payload), content_type="application/json")

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_anonymous_and_nonstaff_cannot_read_or_write(self, relay):
        self.assertEqual(self.client.get(self.url).status_code, 302)
        nonstaff = get_user_model().objects.create_user("plain-user", password="test")
        self.client.force_login(nonstaff)
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.assertEqual(self.post({"enabled": False, "expected_revision": 4}).status_code, 302)
        relay.assert_not_called()

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_staff_read_and_superuser_only_write(self, relay):
        relay.return_value = JsonResponse({"ok": True, "policy": {**POLICY, "private": "never-forward"}})
        self.client.force_login(self.staff)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["policy"], POLICY)
        self.assertFalse(response.json()["can_change"])
        self.assertIn("OPTIX and Dollar", response.json()["scope"])
        self.assertIn("no-store", response["Cache-Control"])
        relay.assert_called_once_with("get", actor="dollar:cooldown-staff")
        relay.reset_mock()
        self.assertEqual(self.post({"enabled": False, "expected_revision": 4}).status_code, 403)
        relay.assert_not_called()

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_superuser_write_uses_server_authenticated_actor(self, relay):
        relay.return_value = JsonResponse({"ok": True, "policy": {**POLICY, "enabled": False, "revision": 5}})
        self.client.force_login(self.admin)
        response = self.post({"enabled": False, "expected_revision": 4})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["can_change"])
        self.assertFalse(response.json()["policy"]["enabled"])
        relay.assert_called_once_with("set", actor="dollar:cooldown-admin", enabled=False, expected_revision=4)

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_malformed_or_forged_inputs_do_not_reach_bridge(self, relay):
        self.client.force_login(self.admin)
        for body in ({}, [], {"enabled": "false", "expected_revision": 4}, {"enabled": 0, "expected_revision": 4},
                     {"enabled": False, "expected_revision": True}, {"enabled": False, "expected_revision": "4"},
                     {"enabled": False, "expected_revision": -1}, {"enabled": False, "expected_revision": 4, "actor": "another-admin"}):
            with self.subTest(body=body):
                self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.client.post(self.url, b"not-json", content_type="application/json").status_code, 400)
        relay.assert_not_called()

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_upstream_unavailable_invalid_and_conflict_never_return_success(self, relay):
        self.client.force_login(self.admin)
        for status in (403, 500, 502, 503):
            with self.subTest(status=status):
                relay.return_value = JsonResponse({"message": "private-upstream-detail"}, status=status)
                response = self.post({"enabled": False, "expected_revision": 4})
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.json()["ok"])
                self.assertNotIn(b"private-upstream-detail", response.content)
        for policy in ({**POLICY, "enabled": "true"}, {**POLICY, "revision": True}, {**POLICY, "cooldown_hours": 12}, {**POLICY, "updated_at": "not-a-date"}):
            relay.return_value = JsonResponse({"ok": True, "policy": policy})
            self.assertEqual(self.client.get(self.url).status_code, 503)
        relay.return_value = JsonResponse({"ok": False}, status=409)
        self.assertEqual(self.post({"enabled": False, "expected_revision": 4}).status_code, 409)

    @patch("control.proxy_cooldown_panel.cooldown_policy")
    def test_post_requires_csrf_and_unsupported_methods_are_denied(self, relay):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        self.assertEqual(csrf_client.post(self.url, json.dumps({"enabled": False, "expected_revision": 4}), content_type="application/json").status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.delete(self.url).status_code, 405)
        relay.assert_not_called()
