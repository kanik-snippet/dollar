import hashlib
import hmac
import io
import json
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from . import warrior_proxy_bridge as bridge


TEST_SECRET = "isolated-cooldown-bridge-test-secret-0001"


@override_settings(WARRIOR_PROXY_BRIDGE_URL="https://warrior.example.test/private/bridge/", WARRIOR_PROXY_BRIDGE_SECRET=TEST_SECRET, WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS=8)
class CooldownPolicyRelayTests(SimpleTestCase):
    @patch("control.warrior_proxy_bridge.time.time", return_value=2000000000)
    @patch("control.warrior_proxy_bridge.urlopen")
    def test_policy_request_has_hmac_and_no_dummy_client(self, urlopen, _clock):
        urlopen.return_value.__enter__.return_value = SimpleNamespace(read=lambda: b'{"ok":true,"policy":{}}', status=200)
        response = bridge.cooldown_policy("set", enabled=False, expected_revision=3, actor="dollar:admin")
        self.assertEqual(response.status_code, 200)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload, {"action": "cooldown-policy", "request": {"operation": "set", "enabled": False, "expected_revision": 3, "actor": "dollar:admin"}})
        expected = hmac.new(TEST_SECRET.encode(), b"2000000000\n" + request.data, hashlib.sha256).hexdigest()
        self.assertEqual(request.get_header("X-optix-signature"), expected)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 8)

    @patch("control.warrior_proxy_bridge.urlopen")
    def test_desktop_relay_cannot_send_administrative_action(self, urlopen):
        self.assertEqual(bridge.relay(None, "cooldown-policy", request={"operation": "set"}).status_code, 403)
        urlopen.assert_not_called()

    @patch("control.warrior_proxy_bridge.urlopen")
    def test_existing_desktop_payload_is_preserved(self, urlopen):
        urlopen.return_value.__enter__.return_value = SimpleNamespace(read=lambda: b'{"allowed":true}', status=200)
        client = SimpleNamespace(office_name="Office", system_number="01", device_id="device")
        response = bridge.relay(client, "claim", request={"exit_ip": "198.51.100.4"})
        self.assertEqual(response.status_code, 200)
        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload["client"], {"office_name": "Office", "system_number": "01", "device_id": ""})
        self.assertEqual(payload["action"], "claim")

    @patch("control.warrior_proxy_bridge.urlopen")
    def test_bridge_failure_and_nonobject_json_fail_closed(self, urlopen):
        for error in (URLError("private details"), TimeoutError(), OSError()):
            with self.subTest(error=type(error).__name__):
                urlopen.side_effect = error
                response = bridge.cooldown_policy("get", actor="staff")
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(b"private details", response.content)
        urlopen.side_effect = None
        for body in (b"not-json", b"[]", b"null", b"\xff"):
            with self.subTest(body=body):
                urlopen.return_value.__enter__.return_value = SimpleNamespace(read=lambda: body, status=200)
                self.assertEqual(bridge.cooldown_policy("get", actor="staff").status_code, 502)

    @patch("control.warrior_proxy_bridge.urlopen")
    def test_http_conflict_is_propagated(self, urlopen):
        urlopen.side_effect = HTTPError("https://warrior.example.test/", 409, "Conflict", {}, io.BytesIO(b'{"ok":false}'))
        self.assertEqual(bridge.cooldown_policy("set", enabled=False, expected_revision=0, actor="admin").status_code, 409)

    @override_settings(WARRIOR_PROXY_BRIDGE_SECRET="")
    @patch("control.warrior_proxy_bridge.urlopen")
    def test_missing_bridge_configuration_never_calls_network(self, urlopen):
        self.assertEqual(bridge.cooldown_policy("get", actor="staff").status_code, 503)
        urlopen.assert_not_called()
