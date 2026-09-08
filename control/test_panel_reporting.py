import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import BootstrapAudit, ClientAccess, ClientAccessIP, ConfigBundle, ProfileActivity, ProfileDomainActivity
from .panel_reporting import HIDE_PERSONAL, REPORT_OFFICES


class PanelReportingTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser("report-admin", "report@example.test", "test-password")
        self.client.force_login(self.admin)
        self.bundle = ConfigBundle.objects.create(name="Reporting test")
        self.devices = []
        for index, office in enumerate(("Spaze 822", "Spaze 822", "Welldone 011", "Personal"), 1):
            self.devices.append(ClientAccess.objects.create(
                name=f"Device {index}", office_name=office, system_number=f"PC{index}",
                device_id=f"report-device-{index}", ipv4=f"198.51.100.{index}", config_bundle=self.bundle,
            ))

    def get_report(self, name, **params):
        response = self.client.get(reverse("control:" + name), params)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_sidebar_exposes_both_reports_without_changing_brand(self):
        response = self.client.get(reverse("control:panel"))
        self.assertContains(response, 'data-route="audit"')
        self.assertContains(response, 'data-route="domains"')
        self.assertContains(response, 'panel-audit.js')
        self.assertContains(response, 'data-notifications-url=')

    def test_reports_are_staff_only(self):
        self.client.logout()
        for name in ("panel-office-reports-api", "panel-domain-reports-api", "panel-notifications-api"):
            response = self.client.get(reverse("control:" + name))
            self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.create_user("not-staff", password="test-password")
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("control:panel-office-reports-api")).status_code, 302)

    def test_opened_profiles_are_per_pc_distinct_and_only_confirmed(self):
        for device in self.devices:
            for status in ("proxy_reserved", "profile_created", "profile_opened", "profile_opened", "profile_open_failed"):
                ProfileActivity.objects.create(client=device, profile_id="same-id", status=status)
        data = self.get_report("panel-office-reports-api", office="Spaze 822", range="24h")
        self.assertEqual(data["metrics"]["opened"], 2)
        self.assertEqual(data["metrics"]["open_events"], 4)
        self.assertEqual(data["metrics"]["attempts"], 2)
        self.assertEqual(len(data["rows"]), 2)
        self.assertTrue(all(row["opened"] == 1 for row in data["rows"]))
        self.assertTrue(set(REPORT_OFFICES).issubset(data["offices"]))
        if HIDE_PERSONAL:
            self.assertNotIn("Personal", data["offices"])
            data = self.get_report("panel-office-reports-api", office="Personal")
            self.assertNotEqual(data["office"], "Personal")
        else:
            self.assertIn("Personal", data["offices"])

    def test_audit_is_paginated_and_uses_exact_time_boundary(self):
        start = timezone.now() - timedelta(hours=2)
        end = timezone.now()
        for index in range(31):
            row = ProfileActivity.objects.create(client=self.devices[0], profile_id=str(index), status="profile_opened")
            ProfileActivity.objects.filter(pk=row.pk).update(created_at=start)
        row = ProfileActivity.objects.create(client=self.devices[0], profile_id="outside", status="profile_opened")
        ProfileActivity.objects.filter(pk=row.pk).update(created_at=end)
        data = self.get_report("panel-office-reports-api", **{"office":"Spaze 822", "view":"events", "page":2, "page_size":10, "from":start.isoformat(), "to":end.isoformat()})
        self.assertEqual(data["metrics"]["opened"], 31)
        self.assertEqual(data["pagination"]["total"], 31)
        self.assertEqual(len(data["rows"]), 10)

    def test_domains_are_office_scoped_and_count_profile_ids_per_pc(self):
        now = timezone.now()
        for device in self.devices:
            ProfileDomainActivity.objects.create(
                client=device, profile_id="same-id", session_id="s1", domain="example.test",
                first_visited_at=now, last_visited_at=now, session_started_at=now, session_ended_at=now, visit_count=3,
            )
        data = self.get_report("panel-domain-reports-api", office="Spaze 822", q="example.test")
        self.assertEqual(data["metrics"]["profiles"], 2)
        self.assertEqual(data["metrics"]["visits"], 6)
        self.assertEqual(len(data["rows"]), 2)
        self.assertTrue(all(row["office_name"] == "Spaze 822" for row in data["rows"]))
        self.assertNotIn("url", data["rows"][0])
        self.assertEqual(self.get_report("panel-domain-reports-api", office="Spaze 822", q="missing.test")["rows"], [])

    def test_hidden_or_other_office_device_filter_cannot_leak_data(self):
        self.assertEqual(self.get_report("panel-office-reports-api", office="Spaze 822", client=self.devices[-1].pk)["rows"], [])
        self.assertEqual(self.get_report("panel-domain-reports-api", office="Spaze 822", client="bad-id")["rows"], [])
        for client_id in ("²", "9"*5000, "-1"):
            self.assertEqual(self.get_report("panel-office-reports-api", office="Spaze 822", client=client_id)["rows"], [])

    def test_only_personal_cannot_leak_into_warrior_access(self):
        if not HIDE_PERSONAL:
            return
        ClientAccess.objects.exclude(office_name="Personal").delete()
        data = self.get_report("panel-access-api")
        self.assertEqual(data["rows"], [])

    def test_notification_unread_count_is_not_capped_by_history_page(self):
        audits = [BootstrapAudit(client=self.devices[0], device_id=self.devices[0].device_id, reason="not-whitelisted", allowed=False) for _ in range(215)]
        BootstrapAudit.objects.bulk_create(audits)
        data = self.get_report("panel-notifications-api", page_size=10, page=2)
        self.assertEqual(data["unread_count"], 215)
        self.assertEqual(len(data["notifications"]), 10)
        self.assertEqual(data["pagination"]["total"], 215)
        row_id = data["notifications"][0]["id"]
        response = self.client.post(reverse("control:panel-access-api"), data=json.dumps({"action":"mark_read","audit_id":row_id}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.get_report("panel-notifications-api")["unread_count"], 214)
        self.assertEqual(self.get_report("panel-notifications-api", notification_filter="all")["pagination"]["total"], 215)

    def test_personal_visibility_is_brand_specific_and_unknown_requests_are_visible(self):
        for linked in (True, False):
            BootstrapAudit.objects.create(client=self.devices[-1] if linked else None, device_id=self.devices[-1].device_id, reason="not-whitelisted")
        unknown = BootstrapAudit.objects.create(device_id="unknown-device", reason="not-whitelisted")
        data = self.get_report("panel-notifications-api")
        self.assertEqual(data["unread_count"], 1 if HIDE_PERSONAL else 3)
        row = next(row for row in data["notifications"] if row["id"] == unknown.pk)
        self.assertEqual(row["office"], "Unassigned")
        self.assertFalse(row["can_approve"])

    def test_activation_denial_is_visible_but_cannot_be_ip_approved(self):
        audit = BootstrapAudit.objects.create(client=self.devices[0], reason="activation-required", observed_ip="203.0.113.11")
        data = self.get_report("panel-notifications-api")
        self.assertFalse(data["notifications"][0]["can_approve"])
        response = self.client.post(reverse("control:panel-access-api"), data=json.dumps({"action":"approve_request","audit_id":audit.pk}), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ClientAccessIP.objects.count(), 0)
        audit.refresh_from_db()
        self.assertEqual(audit.review_status, "pending")
