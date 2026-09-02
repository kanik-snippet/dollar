from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import BootstrapAudit, ClientAccess, ConfigBundle


class BootstrapAuditWhitelistAdminTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="whitelist-admin",
            email="admin@example.com",
            password="test-password",
        )
        self.client.force_login(self.user)
        self.bundle = ConfigBundle.objects.create(name="Main", active=True)

    def _whitelist_url(self, audit):
        return reverse(
            "admin:control_bootstrapaudit_whitelist",
            args=(audit.pk,),
        )

    @override_settings(TRUST_APP_REPORTED_IPV4=True)
    def test_whitelist_prefills_access_form_with_reported_ip_and_device(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="100.64.0.5",
            reported_ip="203.0.113.71",
            device_id="device-new-123456789",
            allowed=False,
            reason="not-whitelisted",
            app_version="1.7.14",
        )

        response = self.client.get(self._whitelist_url(audit))

        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, reverse("admin:control_clientaccess_add"))
        params = parse_qs(location.query)
        self.assertEqual(params["ipv4"], ["203.0.113.71"])
        self.assertEqual(params["device_id"], ["device-new-123456789"])
        self.assertEqual(params["active"], ["1"])
        self.assertEqual(params["config_bundle"], [str(self.bundle.pk)])
        self.assertIn(f"Bootstrap Audit #{audit.pk}", params["notes"][0])

    @override_settings(TRUST_APP_REPORTED_IPV4=False)
    def test_whitelist_uses_observed_ip_when_reported_ip_is_not_trusted(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="198.51.100.41",
            reported_ip="203.0.113.99",
            device_id="device-observed",
            allowed=False,
            reason="not-whitelisted",
        )

        response = self.client.get(self._whitelist_url(audit))
        params = parse_qs(urlsplit(response["Location"]).query)

        self.assertEqual(params["ipv4"], ["198.51.100.41"])

    @override_settings(TRUST_APP_REPORTED_IPV4=True)
    def test_existing_access_record_opens_instead_of_creating_duplicate(self):
        access = ClientAccess.objects.create(
            name="Existing device",
            ipv4="203.0.113.81",
            device_id="existing-device",
            active=False,
            office_name="MH",
            system_number="2",
            config_bundle=self.bundle,
        )
        audit = BootstrapAudit.objects.create(
            client=access,
            observed_ip="100.64.0.8",
            reported_ip="203.0.113.81",
            device_id="existing-device",
            allowed=False,
            reason="inactive",
        )

        response = self.client.get(self._whitelist_url(audit))

        self.assertEqual(
            response["Location"],
            reverse("admin:control_clientaccess_change", args=(access.pk,)),
        )
        self.assertEqual(
            ClientAccess.objects.filter(
                ipv4="203.0.113.81",
                device_id="existing-device",
            ).count(),
            1,
        )

    def test_bootstrap_audit_changelist_shows_whitelist_action(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="198.51.100.42",
            reported_ip="203.0.113.82",
            device_id="device-button",
            allowed=False,
            reason="not-whitelisted",
        )

        response = self.client.get(reverse("admin:control_bootstrapaudit_changelist"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self._whitelist_url(audit))
        self.assertContains(response, "Whitelist")
