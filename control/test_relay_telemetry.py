"""Dollar proxy relay telemetry must not link Warrior IDs to local rows."""
import json
from unittest.mock import patch

from django.core import signing
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import ClientAccess, ConfigBundle, ProfileActivity, ProfileDomainActivity, ProxyGenerationJob, ProxyReservation
from .views import TOKEN_SALT


@override_settings(TRUST_APP_REPORTED_IPV4=False, TRUST_PROXY_HEADERS=False, LOCAL_TESTING_MODE=False)
class RelayTelemetryTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle.objects.create(name="Telemetry")
        self.device = ClientAccess.objects.create(name="Local Dollar PC", office_name="Personal", device_id="dollar-device", ipv4="198.51.100.40", config_bundle=self.bundle)
        self.other = ClientAccess.objects.create(name="Other PC", device_id="other-device", ipv4="198.51.100.41", config_bundle=self.bundle)
        self.job = ProxyGenerationJob.objects.create(client=self.other, provider_code="P3", country_code="US")
        self.reservation = ProxyReservation.objects.create(client=self.other, job=self.job, provider_code="P3", country_code="US", proxy_fingerprint="a"*64)
        token = signing.dumps({"client_id":self.device.pk,"ip":self.device.ipv4,"device_id":self.device.device_id,"config_version":self.bundle.version}, salt=TOKEN_SALT)
        self.headers = {"HTTP_AUTHORIZATION":"Bearer "+token,"HTTP_X_DEVICE_ID":self.device.device_id,"REMOTE_ADDR":self.device.ipv4}

    def post(self, name, body, headers=None):
        return self.client.post(reverse("control:"+name), data=json.dumps(body), content_type="application/json", **(self.headers if headers is None else headers))

    def lifecycle(self):
        return {"job_id":self.job.pk,"reservation_id":self.reservation.pk,"status":"profile_opened","profile_id":"browser-profile-1"}

    def domain_batch(self):
        now = timezone.now().isoformat()
        return {**self.lifecycle(),"session_id":"session-1","session_started_at":now,"session_ended_at":now,"domains":[{"domain":"example.test","first_visited_at":now,"last_visited_at":now,"visit_count":2}]}

    @patch("control.views.warrior_proxy_enabled", return_value=True)
    def test_remote_ids_cannot_link_to_other_local_client(self, _enabled):
        response = self.post("profile-activity", self.lifecycle())
        self.assertEqual(response.status_code, 201)
        row = ProfileActivity.objects.get()
        self.assertEqual(row.client, self.device)
        self.assertIsNone(row.job_id)
        self.assertIsNone(row.reservation_id)
        body = self.domain_batch()
        self.assertEqual(self.post("profile-domains", body).status_code, 201)
        self.assertEqual(self.post("profile-domains", body).status_code, 201)
        row = ProfileDomainActivity.objects.get()
        self.assertEqual(row.client, self.device)
        self.assertIsNone(row.job_id)
        self.assertIsNone(row.reservation_id)
        self.assertEqual(row.visit_count, 2)
        self.reservation.refresh_from_db()
        self.assertEqual(self.reservation.profile_id, "")

    @patch("control.views.warrior_proxy_enabled", return_value=False)
    def test_local_ownership_checks_remain_enforced(self, _enabled):
        self.assertEqual(self.post("profile-activity", self.lifecycle()).status_code, 403)
        self.assertEqual(self.post("profile-domains", self.domain_batch()).status_code, 400)
        self.assertFalse(ProfileActivity.objects.exists())
        self.assertFalse(ProfileDomainActivity.objects.exists())
        self.job.client=self.device
        self.job.save()
        self.reservation.client=self.device
        self.reservation.save()
        self.assertEqual(self.post("profile-activity", self.lifecycle()).status_code, 201)
        self.assertEqual(ProfileActivity.objects.get().job_id, self.job.pk)

    @patch("control.views.warrior_proxy_enabled", return_value=True)
    def test_invalid_ids_and_unauthenticated_devices_are_rejected(self, _enabled):
        for value in ("bad", -1, 0, True, 1.5, str(2**65)):
            body=self.lifecycle()
            body["job_id"]=value
            self.assertEqual(self.post("profile-activity", body).status_code, 403)
        self.assertEqual(self.post("profile-activity", self.lifecycle(), headers={}).status_code, 403)
        self.assertEqual(self.post("profile-domains", self.domain_batch(), headers={}).status_code, 403)
        wrong={**self.headers,"HTTP_X_DEVICE_ID":"someone-else"}
        self.assertEqual(self.post("profile-activity", self.lifecycle(), headers=wrong).status_code, 403)
        self.assertFalse(ProfileActivity.objects.exists())

