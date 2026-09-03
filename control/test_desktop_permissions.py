from django.test import TestCase

from .models import ClientAccess, ConfigBundle, DesktopOfficeAccessPolicy
from .views import _desktop_runtime_values, _provider_is_allowed


class DesktopAccessPolicyTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle.objects.create(name="permissions-test")
        self.client = ClientAccess.objects.create(
            name="PC 1",
            ipv4="203.0.113.10",
            device_id="permissions-device",
            office_name="Office A",
            system_number="1",
            config_bundle=self.bundle,
        )

    def test_global_defaults_are_safe_and_complete(self):
        resolved = DesktopOfficeAccessPolicy.resolve_for(self.client)
        self.assertEqual(resolved["source"], "global-default")
        self.assertEqual(resolved["providers"], ["P1", "P2", "P3", "P4"])
        self.assertEqual(resolved["browsers"], ["B1", "B2"])
        self.assertEqual(resolved["devices"], ["desktop", "mobile"])
        self.assertFalse(resolved["show_logs"])

    def test_office_policy_is_inherited(self):
        DesktopOfficeAccessPolicy.objects.create(
            office_name="office a",
            allowed_provider_codes=["p3", "P1", "p3"],
            allowed_browser_codes=["b1"],
            allowed_device_codes=["DESKTOP"],
            show_logs=True,
        )
        resolved = DesktopOfficeAccessPolicy.resolve_for(self.client)
        self.assertEqual(resolved["source"], "office")
        self.assertEqual(resolved["providers"], ["P3", "P1"])
        self.assertEqual(resolved["browsers"], ["B1"])
        self.assertEqual(resolved["devices"], ["desktop"])
        self.assertTrue(resolved["show_logs"])
        self.assertTrue(_provider_is_allowed(self.client, "p3"))
        self.assertFalse(_provider_is_allowed(self.client, "P2"))

    def test_device_override_wins_over_office(self):
        DesktopOfficeAccessPolicy.objects.create(
            office_name="Office A",
            allowed_provider_codes=["P1", "P3"],
            allowed_browser_codes=["B1", "B2"],
            allowed_device_codes=["desktop", "mobile"],
            show_logs=True,
        )
        self.client.desktop_permissions_override = True
        self.client.allowed_provider_codes = ["P2"]
        self.client.allowed_browser_codes = ["B1"]
        self.client.allowed_device_codes = ["mobile"]
        self.client.show_logs_override = False
        self.client.save()
        resolved = DesktopOfficeAccessPolicy.resolve_for(self.client)
        self.assertEqual(resolved["source"], "device")
        self.assertEqual(resolved["providers"], ["P2"])
        self.assertEqual(resolved["browsers"], ["B1"])
        self.assertEqual(resolved["devices"], ["mobile"])
        self.assertFalse(resolved["show_logs"])

    def test_runtime_options_are_filtered_to_policy(self):
        resolved = {
            "source": "office",
            "office_name": "Office A",
            "providers": ["P3"],
            "browsers": ["B1"],
            "devices": ["desktop"],
            "show_logs": True,
        }
        values = _desktop_runtime_values(
            {
                "providers": [{"id": "P1", "name": "One"}, {"id": "P3", "name": "Three"}],
                "browsers": [{"id": "B1", "name": "Electron"}, {"id": "B2", "name": "Octo"}],
                "devices": [{"id": "desktop", "name": "Desktop"}, {"id": "mobile", "name": "Mobile"}],
                "features": {"anotherFeature": True},
            },
            resolved,
            [{"id": "P3", "name": "Three"}],
        )
        self.assertEqual([row["id"] for row in values["providers"]], ["P3"])
        self.assertEqual([row["id"] for row in values["browsers"]], ["B1"])
        self.assertEqual([row["id"] for row in values["devices"]], ["desktop"])
        self.assertTrue(values["features"]["showLogs"])
        self.assertTrue(values["features"]["anotherFeature"])
        self.assertTrue(values["runtime"]["features"]["showLogs"])
