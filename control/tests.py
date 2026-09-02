from __future__ import annotations

import base64
import io
import json
import re
import tempfile
import zipfile
from datetime import timedelta
from threading import Barrier, Lock, Thread
from unittest import mock
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import close_old_connections
from django.test import (
    SimpleTestCase,
    TestCase,
    TransactionTestCase,
    override_settings,
    skipUnlessDBFeature,
)
from django.urls import reverse
from django.utils import timezone

from .admin import DesktopComponentReleaseForm, DesktopReleaseForm, import_catalog_zip
from .geo_catalog import (
    ensure_global_country_catalog,
    ensure_p4_region_catalog,
    p2_geo_account_key,
)
from .models import (
    BootstrapAudit, ClientAccess, ClientAccessIP, ConfigBundle, DesktopComponentRelease, DesktopRelease, ExtensionPackage, ProfileDomainActivity,
    MonitoredDomain, Provider, ProxyCityCatalog, ProxyCountryFile,
    ProxyExitIPCooldown, ProxyGenerationJob, ProxyInventoryAlert, ProxyPoolEntry, ProxyPoolTarget,
    ProxyReservation, ProfileCreateLease, ProfileCreateQueue, ProxyRegionCatalog,
)
from .exit_ip_cooldown import claim_exit_ip
from .release_updates import (
    canonical_component_payload,
    canonical_release_payload,
    verify_component_signature,
    verify_release_signature,
)
from .management.commands.prefill_p2_geo_pools import _sync_city_catalog
from .proxy_jobs import reserve_pool_proxies
from .tasks import (
    _generate, ensure_pool_targets, provider_is_configured, queue_refill_proxy_pool,
    refill_proxy_pool,
)
from .views import (
    _decode_p3_legacy_location,
    _legacy_p3_location_catalog,
    _legacy_p3_location_id,
    _legacy_p3_location_rows,
)


class LegacyP3LocationTests(SimpleTestCase):
    def test_legacy_aliases_decode_to_existing_prefill_dimensions(self):
        self.assertEqual(
            _decode_p3_legacy_location(
                "P3",
                _legacy_p3_location_id("region", "GB", "ENG"),
                "",
                "",
            ),
            ("GB", "ENG", ""),
        )
        self.assertEqual(
            _decode_p3_legacy_location(
                "P3",
                _legacy_p3_location_id("city", "GB", "London"),
                "",
                "",
            ),
            ("GB", "", "London"),
        )
        self.assertEqual(
            _decode_p3_legacy_location("P3", "UK", "", ""),
            ("GB", "", ""),
        )

    def test_legacy_flat_catalog_is_limited_to_selected_offices_and_versions(self):
        client = ClientAccess(office_name="Spaze 822")
        self.assertTrue(_legacy_p3_location_catalog(client, "1.7.33.0"))
        self.assertFalse(_legacy_p3_location_catalog(client, "1.7.34"))
        client.office_name = "Another office"
        self.assertFalse(_legacy_p3_location_catalog(client, "1.7.33"))

    def test_legacy_flat_rows_include_country_state_and_city_choices(self):
        country = ProxyCountryFile(
            country_code="GB",
            country_name="United Kingdom",
            version=1,
            content_sha256="",
        )
        rows = _legacy_p3_location_rows([country])
        identifiers = {row["id"] for row in rows}
        self.assertIn("GB", identifiers)
        self.assertIn(
            _legacy_p3_location_id("region", "GB", "ENG"),
            identifiers,
        )
        self.assertIn(
            _legacy_p3_location_id("city", "GB", "London"),
            identifiers,
        )
        self.assertTrue(
            all(
                re.fullmatch(r"[A-Za-z0-9_-]{1,32}", identifier)
                for identifier in identifiers
            )
        )


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    TRUST_APP_REPORTED_IPV4=False,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
    PROFILE_CREATE_SERIALIZATION_ENABLED=True,
)
class ControlApiTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(
            name="Office config",
            version=7,
            browser_group_id="2255",
            browser_group_name="Testing",
        )
        self.bundle.set_payload(
            {
                "APP_API_KEY": "browser-secret",
                "TUBELIGHT_API_KEY": "tubelight-secret",
                "P1_PASSWORD": "proxy-secret",
                "P2_ACCOUNT_EMAIL": "office-a@example.test",
            }
        )
        self.bundle.save()
        self.p2_account_key = p2_geo_account_key("office-a@example.test")
        self.client_access = ClientAccess.objects.create(
            name="Office system 1",
            ipv4="203.0.113.10",
            device_id="device-one",
            office_name="1115",
            system_number="1",
            profile_name="Device Alpha",
            config_bundle=self.bundle,
        )
        self.provider = Provider.objects.create(
            code="P1", display_name="P1", display_order=1
        )
        self.country = ProxyCountryFile(
            provider=self.provider,
            country_code="US",
            country_name="United States",
        )
        self.country.set_content("host:1000:user:pass\nhost:1001:user:pass\n")
        self.country.save()

    def bootstrap(
        self,
        reported="203.0.113.10",
        remote="203.0.113.10",
        device_id="device-one",
    ):
        return self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps(
                {
                    "reported_ipv4": reported,
                    "app_version": "1.6.1",
                    "device_id": device_id,
                }
            ),
            content_type="application/json",
            REMOTE_ADDR=remote,
        )

    def test_zip_catalog_import_replaces_existing_and_adds_new_country(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("P1/US__United States.txt", "new-host:1000:user:pass\n")
            archive.writestr("P1/AU__Australia.txt", "au-host:1000:user:pass\n")
        upload = SimpleUploadedFile("catalog.zip", buffer.getvalue(), content_type="application/zip")
        imported, replaced = import_catalog_zip(upload)
        self.assertEqual((imported, replaced), (2, 1))
        us = ProxyCountryFile.objects.get(provider__code="P1", country_code="US")
        au = ProxyCountryFile.objects.get(provider__code="P1", country_code="AU")
        self.assertEqual(us.get_content(), "new-host:1000:user:pass\n")
        self.assertEqual(au.country_name, "Australia")
        self.assertTrue(au.active)

    def test_encrypted_fields_do_not_store_plaintext(self):
        self.assertNotIn("browser-secret", self.bundle.payload_ciphertext)
        self.assertNotIn("host:1000", self.country.content_ciphertext)
        self.assertEqual(self.bundle.get_payload()["APP_API_KEY"], "browser-secret")

    def test_public_ipv4_endpoint_returns_server_observed_ip(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True, "ipv4": "203.0.113.10"})
        self.assertIn("no-store", response["Cache-Control"])

    def test_non_whitelisted_ip_is_denied(self):
        response = self.bootstrap(reported="203.0.113.99", remote="203.0.113.99")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"allowed": False, "message": "Access denied."})

    def test_reported_ip_must_match_observed_ip(self):
        response = self.bootstrap(reported="203.0.113.11")
        self.assertEqual(response.status_code, 403)

    @override_settings(TRUST_APP_REPORTED_IPV4=True)
    def test_approved_app_reported_ip_drives_whitelist_and_proxy_token(self):
        response = self.bootstrap(
            reported="203.0.113.10",
            remote="100.64.0.19",
            device_id="device-one",
        )
        self.assertEqual(response.status_code, 200)
        token = response.json()["access_token"]
        proxy_response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="100.64.0.21",
        )
        self.assertEqual(proxy_response.status_code, 200)

        changed_ip = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.11",
            REMOTE_ADDR="100.64.0.21",
        )
        self.assertEqual(changed_ip.status_code, 403)

    def test_unknown_device_on_allowed_ip_is_denied(self):
        response = self.bootstrap(device_id="not-authorized")
        self.assertEqual(response.status_code, 403)

    @mock.patch("control.views.cache.add", side_effect=RuntimeError("redis unavailable"))
    def test_bootstrap_remains_available_when_rate_limit_cache_fails(self, _cache_add):
        response = self.bootstrap()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed"])

    def test_allowed_bootstrap_merges_per_client_values(self):
        response = self.bootstrap()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["tubelight_config"]["OFFICE_NAME"], "1115")
        self.assertEqual(payload["tubelight_config"]["SYSTEM_NUMBER"], "1")
        self.assertEqual(payload["tubelight_config"]["APP_API_KEY"], "browser-secret")
        self.assertEqual(payload["tubelight_config"]["BROWSER_GROUP_ID"], "2255")
        self.assertEqual(payload["tubelight_config"]["BROWSER_GROUP_NAME"], "Testing")
        self.assertEqual(payload["tubelight_config"]["DEVICE_PROFILE_NAME"], "Device Alpha")
        self.assertEqual(
            payload["assignment"],
            {
                "browser_group_id": "2255",
                "browser_group_name": "Testing",
                "profile_name": "Device Alpha",
            },
        )
        self.assertEqual(payload["catalog"]["providers"][0]["id"], "P1")
        self.assertEqual(response["Cache-Control"], "no-store, no-cache, must-revalidate, private")

    def test_bootstrap_delivers_active_extension_and_authenticated_zip(self):
        package = ExtensionPackage(
            name="Audit extension",
            filename="audit-extension.zip",
            version=3,
            active=True,
            status=True,
            is_top=True,
        )
        package.set_package(b"PK\x03\x04test-extension")
        package.save()

        bootstrap = self.bootstrap().json()
        row = bootstrap["catalog"]["extensions"][0]
        self.assertEqual(row["id"], package.pk)
        self.assertTrue(row["status"])
        self.assertTrue(row["is_top"])
        response = self.client.get(
            reverse("control:extension-package", args=(package.pk,)),
            HTTP_AUTHORIZATION=f"Bearer {bootstrap['access_token']}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"PK\x03\x04test-extension")

    def test_bootstrap_delivers_every_packaged_extension_and_status(self):
        first = ExtensionPackage(
            name="First extension",
            filename="first.zip",
            active=False,
            status=True,
        )
        first.set_package(b"PK\x03\x04first")
        first.save()
        second = ExtensionPackage(
            name="Second extension",
            filename="second.zip",
            active=True,
            status=False,
        )
        second.set_package(b"PK\x03\x04second")
        second.save()
        ExtensionPackage.objects.create(
            name="Missing package",
            filename="missing.zip",
            active=True,
            status=True,
        )

        bootstrap = self.bootstrap().json()
        rows = {
            row["id"]: row
            for row in bootstrap["catalog"]["extensions"]
        }
        self.assertEqual(set(rows), {first.pk, second.pk})
        self.assertTrue(rows[first.pk]["status"])
        self.assertFalse(rows[second.pk]["status"])

        response = self.client.get(
            reverse("control:extension-package", args=(first.pk,)),
            HTTP_AUTHORIZATION=f"Bearer {bootstrap['access_token']}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"PK\x03\x04first")

    def test_same_public_ip_can_have_multiple_authorized_systems(self):
        ClientAccess.objects.create(
            name="Office system 2",
            ipv4="203.0.113.10",
            device_id="device-two",
            office_name="1115",
            system_number="2",
            profile_name="Device Beta",
            config_bundle=self.bundle,
        )
        response = self.bootstrap(device_id="device-two")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["tubelight_config"]["SYSTEM_NUMBER"], "2")
        self.assertEqual(
            response.json()["tubelight_config"]["DEVICE_PROFILE_NAME"],
            "Device Beta",
        )

    def test_assignment_defaults_to_testing_and_client_name(self):
        self.bundle.browser_group_id = ""
        self.bundle.browser_group_name = ""
        self.bundle.save(update_fields=("browser_group_id", "browser_group_name"))
        self.client_access.profile_name = ""
        self.client_access.save(update_fields=("profile_name",))

        response = self.bootstrap()

        self.assertEqual(response.status_code, 200)
        config = response.json()["tubelight_config"]
        self.assertEqual(config["BROWSER_GROUP_ID"], "")
        self.assertEqual(config["BROWSER_GROUP_NAME"], "Testing")
        self.assertEqual(config["DEVICE_PROFILE_NAME"], "Office system 1")

    def test_ip_only_entry_accepts_blank_device_id(self):
        ClientAccess.objects.create(
            name="IP only office",
            ipv4="203.0.113.12",
            device_id="",
            office_name="shared",
            system_number="1",
            config_bundle=self.bundle,
        )
        response = self.bootstrap(
            reported="203.0.113.12",
            remote="203.0.113.12",
            device_id="",
        )
        self.assertEqual(response.status_code, 200)

    def test_proxy_content_requires_valid_ip_bound_bearer(self):
        token = self.bootstrap().json()["access_token"]
        response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["content"], "host:1000:user:pass\nhost:1001:user:pass\n")

        changed_ip = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.11",
        )
        self.assertEqual(changed_ip.status_code, 403)

        changed_device = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-two",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(changed_device.status_code, 403)

    def test_proxy_job_reserves_each_static_line_once_and_records_activity(self):
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "US", "count": 1}),
            content_type="application/json", **headers,
        )
        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["status"], "ready")
        self.assertEqual(len(job["proxies"]), 1)
        self.assertNotIn("host:1000", ProxyReservation.objects.get(pk=job["proxies"][0]["reservation_id"]).proxy_ciphertext)

        second = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "US", "count": 2}),
            content_type="application/json", **headers,
        )
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.json()["job"]["ready_count"], 1)
        self.assertEqual(second.json()["job"]["status"], "partial")

        activity = self.client.post(
            reverse("control:profile-activity"),
            data=json.dumps({
                "job_id": job["id"], "reservation_id": job["proxies"][0]["reservation_id"],
                "status": "opened", "group_id": "8", "profile_name": "1115_sys_1_1",
                "profile_id": "profile-1", "start_urls": ["https://example.test/"],
            }),
            content_type="application/json", **headers,
        )
        self.assertEqual(activity.status_code, 201)

    def test_proxy_job_keeps_profile_count_separate_from_quality_candidates(self):
        self.country.set_content(
            "\n".join(
                f"host:{port}:user:pass"
                for port in range(2000, 2005)
            )
            + "\n"
        )
        self.country.save()
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P1",
                "country": "US",
                "count": 2,
                "candidate_count": 5,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["submitted_count"], 2)
        self.assertEqual(job["requested_count"], 2)
        self.assertEqual(job["candidate_count"], 5)
        self.assertEqual(job["ready_count"], 5)
        self.assertEqual(len(job["proxies"]), 5)
        self.assertEqual(job["status"], "ready")

    @override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
    def test_exit_ip_claim_is_global_and_duplicate_does_not_extend_cooldown(self):
        first_job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P1",
            country_code="US",
        )
        first_reservation = ProxyReservation.objects.create(
            client=self.client_access,
            job=first_job,
            provider_code="P1",
            country_code="US",
            proxy_fingerprint="exit-ip-first-reservation",
        )
        first_token = self.bootstrap().json()["access_token"]
        first_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {first_token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }

        precheck = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps(
                {
                    "action": "check",
                    "provider": "P1",
                    "exit_ip": "198.51.100.44",
                    "job_id": first_job.pk,
                    "reservation_id": first_reservation.pk,
                }
            ),
            content_type="application/json",
            **first_headers,
        )
        self.assertEqual(precheck.status_code, 200)
        self.assertFalse(precheck.json()["duplicate"])
        self.assertEqual(ProxyExitIPCooldown.objects.count(), 0)

        accepted = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps(
                {
                    "action": "claim",
                    "provider": "P1",
                    "exit_ip": "198.51.100.44",
                    "job_id": first_job.pk,
                    "reservation_id": first_reservation.pk,
                    "fraud_score": 12,
                }
            ),
            content_type="application/json",
            **first_headers,
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertTrue(accepted.json()["claimed"])
        self.assertFalse(accepted.json()["duplicate"])
        cooldown = ProxyExitIPCooldown.objects.get()
        original_claimed_at = cooldown.claimed_at
        original_available_after = cooldown.available_after
        self.assertEqual(
            original_available_after - original_claimed_at,
            timedelta(hours=25),
        )

        other_client = ClientAccess.objects.create(
            name="Other office system",
            ipv4="203.0.113.11",
            device_id="device-two",
            office_name="Other office",
            system_number="2",
            config_bundle=self.bundle,
        )
        other_job = ProxyGenerationJob.objects.create(
            client=other_client,
            provider_code="P3",
            country_code="GB",
        )
        other_reservation = ProxyReservation.objects.create(
            client=other_client,
            job=other_job,
            provider_code="P3",
            country_code="GB",
            proxy_fingerprint="exit-ip-other-reservation",
        )
        other_token = self.bootstrap(
            reported="203.0.113.11",
            remote="203.0.113.11",
            device_id="device-two",
        ).json()["access_token"]
        other_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {other_token}",
            "HTTP_X_DEVICE_ID": "device-two",
            "REMOTE_ADDR": "203.0.113.11",
        }
        duplicate_payload = {
            "provider": "P3",
            "exit_ip": "198.51.100.44",
            "job_id": other_job.pk,
            "reservation_id": other_reservation.pk,
        }
        duplicate_check = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps({**duplicate_payload, "action": "check"}),
            content_type="application/json",
            **other_headers,
        )
        self.assertEqual(duplicate_check.status_code, 200)
        self.assertTrue(duplicate_check.json()["duplicate"])

        duplicate_claim = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps({**duplicate_payload, "action": "claim"}),
            content_type="application/json",
            **other_headers,
        )
        self.assertEqual(duplicate_claim.status_code, 200)
        self.assertFalse(duplicate_claim.json()["claimed"])
        self.assertTrue(duplicate_claim.json()["duplicate"])
        self.assertEqual(duplicate_claim.json()["reason"], "exit_ip_cooldown")
        cooldown.refresh_from_db()
        self.assertEqual(cooldown.claimed_at, original_claimed_at)
        self.assertEqual(cooldown.available_after, original_available_after)
        self.assertEqual(cooldown.client, self.client_access)
        self.assertEqual(cooldown.provider_code, "P1")
        self.assertEqual(cooldown.duplicate_attempts, 1)

    @override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
    def test_exit_ip_claim_exact_25_hour_boundary(self):
        job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P1",
            country_code="US",
        )

        def reservation(number):
            return ProxyReservation.objects.create(
                client=self.client_access,
                job=job,
                provider_code="P1",
                country_code="US",
                proxy_fingerprint=f"boundary-reservation-{number}",
            )

        base = timezone.now()
        first = claim_exit_ip(
            client=self.client_access,
            provider_code="P1",
            exit_ip="198.51.100.45",
            job=job,
            reservation=reservation(1),
            now=base,
        )
        self.assertTrue(first.claimed)
        just_before = claim_exit_ip(
            client=self.client_access,
            provider_code="P1",
            exit_ip="198.51.100.45",
            job=job,
            reservation=reservation(2),
            now=base + timedelta(hours=25) - timedelta(microseconds=1),
        )
        self.assertFalse(just_before.claimed)
        self.assertEqual(just_before.cooldown.available_after, base + timedelta(hours=25))

        exact_boundary = claim_exit_ip(
            client=self.client_access,
            provider_code="P1",
            exit_ip="198.51.100.45",
            job=job,
            reservation=reservation(3),
            now=base + timedelta(hours=25),
        )
        self.assertTrue(exact_boundary.claimed)
        self.assertEqual(exact_boundary.cooldown.claimed_at, base + timedelta(hours=25))
        self.assertEqual(exact_boundary.cooldown.available_after, base + timedelta(hours=50))

    @override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
    def test_exit_ip_ipv6_is_normalized_and_unique(self):
        base = timezone.now()
        first = claim_exit_ip(
            client=self.client_access,
            provider_code="P1",
            exit_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
            now=base,
        )
        second = claim_exit_ip(
            client=self.client_access,
            provider_code="P4",
            exit_ip="2001:db8::1",
            now=base + timedelta(seconds=1),
        )
        self.assertTrue(first.claimed)
        self.assertFalse(second.claimed)
        self.assertEqual(ProxyExitIPCooldown.objects.count(), 1)
        self.assertEqual(str(ProxyExitIPCooldown.objects.get().exit_ip), "2001:db8::1")
        self.assertTrue(ProxyExitIPCooldown._meta.get_field("exit_ip").unique)

        mapped = claim_exit_ip(
            client=self.client_access,
            provider_code="P1",
            exit_ip="::ffff:198.51.100.49",
            now=base,
        )
        mapped_duplicate = claim_exit_ip(
            client=self.client_access,
            provider_code="P2",
            exit_ip="198.51.100.49",
            now=base + timedelta(seconds=1),
        )
        self.assertTrue(mapped.claimed)
        self.assertFalse(mapped_duplicate.claimed)
        self.assertTrue(
            ProxyExitIPCooldown.objects.filter(exit_ip="198.51.100.49").exists()
        )

    def test_exit_ip_claim_validates_reservation_ownership_and_payload(self):
        other_client = ClientAccess.objects.create(
            name="Other client",
            ipv4="203.0.113.11",
            device_id="device-two",
            office_name="Other",
            system_number="2",
            config_bundle=self.bundle,
        )
        other_job = ProxyGenerationJob.objects.create(
            client=other_client,
            provider_code="P2",
            country_code="US",
        )
        other_reservation = ProxyReservation.objects.create(
            client=other_client,
            job=other_job,
            provider_code="P2",
            country_code="US",
            proxy_fingerprint="foreign-reservation",
        )
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }
        forbidden = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps(
                {
                    "provider": "P2",
                    "exit_ip": "198.51.100.46",
                    "reservation_id": other_reservation.pk,
                }
            ),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(forbidden.status_code, 403)
        invalid = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps({"provider": "P1", "exit_ip": "not-an-ip"}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertFalse(ProxyExitIPCooldown.objects.exists())

    def test_exit_ip_claim_supports_legacy_path_without_job_or_reservation(self):
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-exit-ip-claim"),
            data=json.dumps(
                {
                    "provider": "P4",
                    "exit_ip": "198.51.100.48",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["claimed"])
        row = ProxyExitIPCooldown.objects.get(exit_ip="198.51.100.48")
        self.assertIsNone(row.job_id)
        self.assertIsNone(row.reservation_id)
        self.assertEqual(row.provider_code, "P4")

    @override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
    def test_same_reservation_score_followup_is_idempotent_without_extending(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
        )
        pool_entry = ProxyPoolEntry(
            target=target,
            proxy_fingerprint="score-followup-pool-entry",
            state="reserved",
            reserved_client=self.client_access,
        )
        pool_entry.set_proxy("host:1000:user:pass")
        pool_entry.save()
        job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P2",
            country_code="US",
        )
        reservation = ProxyReservation.objects.create(
            client=self.client_access,
            job=job,
            pool_entry=pool_entry,
            provider_code="P2",
            country_code="US",
            proxy_fingerprint="score-followup-reservation",
        )
        base = timezone.now()
        first = claim_exit_ip(
            client=self.client_access,
            provider_code="P2",
            exit_ip="198.51.100.47",
            job=job,
            reservation=reservation,
            now=base,
        )
        followup = claim_exit_ip(
            client=self.client_access,
            provider_code="P2",
            exit_ip="198.51.100.47",
            job=job,
            reservation=reservation,
            fraud_score=30,
            now=base + timedelta(minutes=2),
        )
        self.assertTrue(followup.claimed)
        self.assertTrue(followup.idempotent)
        self.assertEqual(followup.cooldown.claimed_at, first.cooldown.claimed_at)
        self.assertEqual(
            followup.cooldown.available_after,
            first.cooldown.available_after,
        )
        self.assertEqual(followup.cooldown.fraud_score, 30)
        pool_entry.refresh_from_db()
        self.assertEqual(str(pool_entry.exit_ip), "198.51.100.47")
        self.assertEqual(pool_entry.fraud_score, 30)

        expired_replay = claim_exit_ip(
            client=self.client_access,
            provider_code="P2",
            exit_ip="198.51.100.47",
            job=job,
            reservation=reservation,
            now=base + timedelta(hours=25),
        )
        self.assertTrue(expired_replay.claimed)
        self.assertFalse(expired_replay.idempotent)
        self.assertEqual(expired_replay.cooldown.claimed_at, base + timedelta(hours=25))
        self.assertEqual(
            expired_replay.cooldown.available_after,
            base + timedelta(hours=50),
        )
        competing_reservation = ProxyReservation.objects.create(
            client=self.client_access,
            job=job,
            provider_code="P2",
            country_code="US",
            proxy_fingerprint="score-followup-competitor",
        )
        competing = claim_exit_ip(
            client=self.client_access,
            provider_code="P2",
            exit_ip="198.51.100.47",
            job=job,
            reservation=competing_reservation,
            now=base + timedelta(hours=25),
        )
        self.assertFalse(competing.claimed)

    def test_p2_proxy_job_preserves_state_and_city(self):
        payload = self.bundle.get_payload()
        payload.update({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
            "P2_PROTOCOL": "socks5",
        })
        self.bundle.set_payload(payload)
        self.bundle.save()
        p2 = Provider.objects.create(code="P2", display_name="P2", display_order=2)
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="US",
            country_name="United States",
        )
        ProxyRegionCatalog.objects.create(
            provider=p2,
            country_code="US",
            region_code="1906",
            region_name="New York",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="US",
            region_code="1906",
            city_name="New York",
            source="infatica-live",
        )
        ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            region="1906",
            city="New York",
            target_count=13,
            replenish_below=3,
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "US",
                "region": "1906",
                "city": "New York",
                "count": 1,
                "candidate_count": 2,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["status"], "ready")
        self.assertEqual(job["ready_count"], 2)
        stored = ProxyGenerationJob.objects.get(pk=job["id"])
        self.assertEqual(stored.region, "1906")
        self.assertEqual(stored.city, "New York")
        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            region="1906",
            city="New York",
        )
        self.assertEqual(target.target_count, 13)
        self.assertEqual(target.replenish_below, 3)

    def test_p2_state_pool_is_synchronously_replenished_between_jobs(self):
        payload = self.bundle.get_payload()
        payload.update({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
            "P2_PROTOCOL": "socks5",
        })
        self.bundle.set_payload(payload)
        self.bundle.save()
        p2 = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="US",
            country_name="United States",
        )
        ProxyRegionCatalog.objects.create(
            provider=p2,
            country_code="US",
            region_code="1906",
            region_name="New York",
        )
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            region="1906",
            target_count=73,
            replenish_below=7,
        )
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }

        for _index in range(2):
            response = self.client.post(
                reverse("control:proxy-job-create"),
                data=json.dumps({
                    "provider": "P2",
                    "country": "US",
                    "region": "1906",
                    "count": 1,
                    "candidate_count": 50,
                }),
                content_type="application/json",
                **headers,
            )
            self.assertEqual(response.status_code, 201)
            job = response.json()["job"]
            self.assertEqual(job["status"], "ready")
            self.assertEqual(job["ready_count"], 50)

        target.refresh_from_db()
        self.assertEqual(target.target_count, 73)
        self.assertEqual(target.replenish_below, 7)
        self.assertEqual(target.entries.filter(state="available").count(), 0)
        self.assertEqual(target.entries.filter(state="reserved").count(), 100)
        self.assertEqual(
            target.entries.values("proxy_fingerprint").distinct().count(),
            100,
        )

    def test_p3_country_pool_is_created_and_replenished_between_jobs(self):
        payload = self.bundle.get_payload()
        payload.update({
            "P3_PROXY_USERNAME": "massive-user",
            "P3_API_KEY": "massive-password",
            "P3_PROTOCOL": "http",
        })
        self.bundle.set_payload(payload)
        self.bundle.save()
        p3 = Provider.objects.create(
            code="P3", display_name="P3", display_order=3
        )
        ProxyCountryFile.objects.create(
            provider=p3,
            country_code="US",
            country_name="United States",
        )
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }

        for _index in range(2):
            response = self.client.post(
                reverse("control:proxy-job-create"),
                data=json.dumps({
                    "provider": "P3",
                    "country": "US",
                    "count": 1,
                    "candidate_count": 50,
                }),
                content_type="application/json",
                **headers,
            )
            self.assertEqual(response.status_code, 201)
            job = response.json()["job"]
            self.assertEqual(job["status"], "ready")
            self.assertEqual(job["ready_count"], 50)

        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle,
            provider_code="P3",
            country_code="US",
            region="",
            city="",
        )
        self.assertEqual(target.target_count, 1000)
        self.assertEqual(target.replenish_below, 200)
        self.assertEqual(target.entries.filter(state="available").count(), 0)
        self.assertEqual(target.entries.filter(state="reserved").count(), 100)
        self.assertEqual(
            target.entries.values("proxy_fingerprint").distinct().count(),
            100,
        )

    def test_dynamic_proxy_job_rejects_unknown_country(self):
        p2 = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="US",
            country_name="United States",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "ZZ",
                "count": 1,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["allowed"])
        self.assertFalse(ProxyGenerationJob.objects.exists())
        self.assertFalse(ProxyPoolTarget.objects.filter(provider_code="P2").exists())

    def test_dynamic_proxy_job_rejects_inactive_country(self):
        p2 = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="US",
            country_name="United States",
            active=False,
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "US",
                "count": 1,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["allowed"])
        self.assertFalse(ProxyGenerationJob.objects.exists())
        self.assertFalse(ProxyPoolTarget.objects.filter(provider_code="P2").exists())

    def test_dynamic_proxy_job_rejects_inactive_provider(self):
        p3 = Provider.objects.create(
            code="P3", display_name="P3", display_order=3, active=False
        )
        ProxyCountryFile.objects.create(
            provider=p3,
            country_code="GB",
            country_name="United Kingdom",
        )
        ProxyCityCatalog.objects.create(
            provider=p3,
            account_key="p3-global-v1",
            country_code="GB",
            region_code="",
            city_name="London",
            source="dynamic-geo-v1",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P3",
                "country": "GB",
                "count": 1,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["allowed"])
        self.assertFalse(ProxyGenerationJob.objects.exists())
        self.assertFalse(ProxyPoolTarget.objects.filter(provider_code="P3").exists())

    def test_p2_country_city_job_instantly_fills_missing_pool_and_caps_candidates(self):
        payload = self.bundle.get_payload()
        payload.update({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
            "P2_PROTOCOL": "socks5",
        })
        self.bundle.set_payload(payload)
        self.bundle.save()
        p2 = Provider.objects.create(code="P2", display_name="P2", display_order=2)
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="GB",
            country_name="United Kingdom",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="GB",
            region_code="850",
            city_name="London",
            source="infatica-live",
        )
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "GB",
                "city": "London",
                "count": 1,
                "candidate_count": 50,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["allowed"])
        job = response.json()["job"]
        self.assertEqual(job["candidate_count"], 40)
        self.assertEqual(job["ready_count"], 40)
        self.assertEqual(job["status"], "ready")
        stored = ProxyGenerationJob.objects.get(pk=job["id"])
        self.assertEqual(stored.region, "")
        self.assertEqual(stored.city, "London")
        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="GB",
            region="",
            city="London",
        )
        self.assertEqual(target.target_count, 40)
        self.assertEqual(target.replenish_below, 8)
        self.assertEqual(target.entries.filter(state="reserved").count(), 40)

    def test_p2_proxy_job_rejects_city_outside_prefilled_catalog(self):
        p2 = Provider.objects.create(code="P2", display_name="P2", display_order=2)
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="US",
            country_name="United States",
        )
        ProxyRegionCatalog.objects.create(
            provider=p2,
            country_code="US",
            region_code="1906",
            region_name="New York",
        )
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "US",
                "region": "1906",
                "city": "New York_city_Injected",
                "count": 1,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["allowed"])

    def test_p3_exact_city_job_caps_candidates_and_instantly_refills(self):
        payload = self.bundle.get_payload()
        payload.update({
            "P3_PROXY_USERNAME": "massive-user",
            "P3_API_KEY": "massive-password",
            "P3_PROTOCOL": "http",
        })
        self.bundle.set_payload(payload)
        self.bundle.save()
        p3 = Provider.objects.create(
            code="P3", display_name="P3", display_order=3
        )
        ProxyCountryFile.objects.create(
            provider=p3,
            country_code="GB",
            country_name="United Kingdom",
        )
        ProxyCityCatalog.objects.create(
            provider=p3,
            account_key="p3-global-v1",
            country_code="GB",
            region_code="",
            city_name="London",
            source="dynamic-geo-v1",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P3",
                "country": "GB",
                "city": "London",
                "count": 1,
                "candidate_count": 50,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["candidate_count"], 40)
        self.assertEqual(job["ready_count"], 40)
        self.assertEqual(job["status"], "ready")
        second = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P3",
                "country": "GB",
                "city": "London",
                "count": 1,
                "candidate_count": 50,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(second.status_code, 201)
        second_job = second.json()["job"]
        self.assertEqual(second_job["candidate_count"], 40)
        self.assertEqual(second_job["ready_count"], 40)
        self.assertEqual(second_job["status"], "ready")
        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle,
            provider_code="P3",
            country_code="GB",
            region="",
            city="London",
        )
        self.assertEqual(target.target_count, 40)
        self.assertEqual(target.replenish_below, 8)
        self.assertEqual(target.entries.filter(state="reserved").count(), 80)

    def test_p2_state_city_catalog_is_independent_of_bundle_inventory(self):
        p2 = Provider.objects.create(code="P2", display_name="P2", display_order=2)
        ProxyRegionCatalog.objects.create(
            provider=p2,
            country_code="US",
            region_code="1906",
            region_name="New York",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="US",
            region_code="1906",
            city_name="New York",
            source="infatica-live",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="US",
            region_code="1906",
            city_name="Albany",
            source="infatica-live",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.get(
            reverse("control:proxy-cities", args=("P2", "US", "1906")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"allowed": True, "cities": ["Albany", "New York"]},
        )

    def test_p2_country_city_catalog_returns_all_shared_cities(self):
        p2 = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="GB",
            region_code="850",
            city_name="London",
            source="infatica-live",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="GB",
            region_code="850",
            city_name="Manchester",
            source="infatica-live",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.get(
            reverse("control:proxy-cities-country", args=("P2", "GB")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"allowed": True, "cities": ["London", "Manchester"]},
        )

    def test_p3_country_city_catalog_is_server_managed(self):
        p3 = Provider.objects.create(
            code="P3", display_name="P3", display_order=3
        )
        ProxyCityCatalog.objects.create(
            provider=p3,
            account_key="p3-global-v1",
            country_code="ID",
            region_code="",
            city_name="Jakarta",
            source="dynamic-geo-v1",
        )
        ProxyCityCatalog.objects.create(
            provider=p3,
            account_key="p3-global-v1",
            country_code="ID",
            region_code="",
            city_name="Denpasar",
            source="dynamic-geo-v1",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.get(
            reverse("control:proxy-cities-country", args=("P3", "ID")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"allowed": True, "cities": ["Denpasar", "Jakarta"]},
        )

    def test_p3_country_city_catalog_remains_available_after_region_selection(self):
        p3 = Provider.objects.create(
            code="P3", display_name="P3", display_order=3
        )
        ProxyRegionCatalog.objects.create(
            provider=p3,
            country_code="ID",
            region_code="JK",
            region_name="Jakarta",
        )
        ProxyCityCatalog.objects.create(
            provider=p3,
            account_key="p3-global-v1",
            country_code="ID",
            region_code="",
            city_name="Jakarta",
            source="dynamic-geo-v1",
        )
        token = self.bootstrap().json()["access_token"]

        response = self.client.get(
            reverse("control:proxy-cities", args=("P3", "ID", "JK")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"allowed": True, "cities": ["Jakarta"]})

    def test_p2_city_list_and_validation_are_isolated_by_geo_account(self):
        p2 = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        ProxyCountryFile.objects.create(
            provider=p2,
            country_code="GB",
            country_name="United Kingdom",
        )
        other_account_key = p2_geo_account_key("office-b@example.test")
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=self.p2_account_key,
            country_code="GB",
            region_code="850",
            city_name="London",
            source="infatica-live",
        )
        ProxyCityCatalog.objects.create(
            provider=p2,
            account_key=other_account_key,
            country_code="GB",
            region_code="850",
            city_name="Leeds",
            source="infatica-live",
        )
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }

        response = self.client.get(
            reverse("control:proxy-cities-country", args=("P2", "GB")),
            **headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"allowed": True, "cities": ["London"]},
        )
        rejected = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({
                "provider": "P2",
                "country": "GB",
                "city": "Leeds",
                "count": 1,
            }),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(rejected.status_code, 403)
        self.assertFalse(rejected.json()["allowed"])

    def test_empty_inventory_does_not_generate_and_records_alert(self):
        token = self.bootstrap().json()["access_token"]
        with mock.patch("control.views.queue_refill_proxy_pool") as queue_refill:
            response = self.client.post(
                reverse("control:proxy-job-create"),
                data=json.dumps({"provider": "P1", "country": "GB", "count": 2}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_X_DEVICE_ID="device-one",
                REMOTE_ADDR="203.0.113.10",
            )

        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["ready_count"], 0)
        self.assertIn("administrator has been notified", job["error"])
        queue_refill.assert_not_called()
        self.assertFalse(
            ProxyPoolTarget.objects.filter(country_code="GB").exists()
        )
        alert = ProxyInventoryAlert.objects.get()
        self.assertEqual(alert.office_name, "1115")
        self.assertEqual(alert.available_count, 0)
        self.assertEqual(alert.requested_count, 2)
        self.assertEqual(alert.status, "disabled")

        second = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "GB", "count": 2}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(second.status_code, 201)
        self.assertEqual(ProxyInventoryAlert.objects.count(), 1)
        alert.refresh_from_db()
        self.assertEqual(alert.occurrence_count, 2)

    @override_settings(
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_CHAT_ID="10001,10002",
        PROXY_ALERT_TIMEOUT_SECONDS=7,
    )
    def test_telegram_inventory_alert_sends_to_each_configured_chat(self):
        from urllib.parse import parse_qs

        from .alerts import send_telegram_proxy_alert

        alert = ProxyInventoryAlert.objects.create(
            dedupe_key="a" * 64,
            client=self.client_access,
            config_bundle=self.bundle,
            office_name="1115",
            system_number="1",
            device_id="device-one",
            provider_code="P1",
            country_code="GB",
            available_count=0,
            requested_count=2,
        )
        first = mock.MagicMock()
        first.__enter__.return_value.read.return_value = json.dumps(
            {"ok": True, "result": {"message_id": 91}}
        ).encode("utf-8")
        second = mock.MagicMock()
        second.__enter__.return_value.read.return_value = json.dumps(
            {"ok": True, "result": {"message_id": 92}}
        ).encode("utf-8")

        with mock.patch(
            "control.alerts.urllib.request.urlopen", side_effect=(first, second)
        ) as urlopen:
            message_ids = send_telegram_proxy_alert(alert)

        self.assertEqual(message_ids, ["91", "92"])
        self.assertEqual(urlopen.call_count, 2)
        first_request = urlopen.call_args_list[0].args[0]
        self.assertEqual(
            first_request.full_url,
            "https://api.telegram.org/bot123456:test-token/sendMessage",
        )
        form = parse_qs(first_request.data.decode("utf-8"))
        self.assertEqual(form["chat_id"], ["10001"])
        self.assertIn("Office: 1115", form["text"][0])
        self.assertIn("P1 GB", form["text"][0])

    def test_expired_profile_lease_does_not_block_the_next_device(self):
        second = ClientAccess.objects.create(
            name="Office system 2",
            ipv4="203.0.113.10",
            device_id="device-two",
            office_name="1115",
            system_number="2",
            profile_name="Device Beta",
            config_bundle=self.bundle,
        )
        first_token = self.bootstrap().json()["access_token"]
        second_token = self.bootstrap(device_id="device-two").json()["access_token"]

        first = self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({"group_id": "2255", "requested_count": 2}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {first_token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertTrue(first.json()["allowed"])

        queued = self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({"group_id": "2255", "requested_count": 2}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {second_token}",
            HTTP_X_DEVICE_ID="device-two",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertTrue(queued.json()["queued"])

        ProfileCreateLease.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        acquired = self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({
                "group_id": "2255",
                "requested_count": 2,
                "request_token": queued.json()["request_token"],
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {second_token}",
            HTTP_X_DEVICE_ID="device-two",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertTrue(acquired.json()["allowed"])
        stale = ProfileCreateQueue.objects.get(client=self.client_access)
        self.assertEqual(stale.status, "expired")
        self.assertEqual(
            ProfileCreateQueue.objects.get(client=second).status,
            "active",
        )

    def test_queued_profile_request_can_be_cancelled(self):
        second = ClientAccess.objects.create(
            name="Office system 2",
            ipv4="203.0.113.10",
            device_id="device-two",
            office_name="1115",
            system_number="2",
            profile_name="Device Beta",
            config_bundle=self.bundle,
        )
        first_token = self.bootstrap().json()["access_token"]
        second_token = self.bootstrap(device_id="device-two").json()["access_token"]
        self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({"group_id": "2255", "requested_count": 1}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {first_token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )
        queued = self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({"group_id": "2255", "requested_count": 1}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {second_token}",
            HTTP_X_DEVICE_ID="device-two",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        ).json()

        response = self.client.post(
            reverse("control:profile-lease-release"),
            data=json.dumps(
                {
                    "group_id": "2255",
                    "request_token": queued["request_token"],
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {second_token}",
            HTTP_X_DEVICE_ID="device-two",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["cancelled"])
        self.assertEqual(
            ProfileCreateQueue.objects.get(client=second).status,
            "expired",
        )

    @override_settings(PROFILE_CREATE_SERIALIZATION_ENABLED=False)
    def test_direct_profile_mode_never_waits_for_a_slot(self):
        token = self.bootstrap().json()["access_token"]
        stale = ProfileCreateLease.objects.create(
            lease_key="profile-create:stale:2255",
            owner_token="stale-owner",
            client=self.client_access,
            group_id="2255",
            requested_count=1,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        # Use the real key so direct mode also proves that legacy blockers are
        # removed. The helper is intentionally local to the view implementation.
        from .views import _profile_lease_key

        stale.lease_key = _profile_lease_key(self.client_access, "2255")
        stale.save(update_fields=("lease_key",))
        response = self.client.post(
            reverse("control:profile-lease-acquire"),
            data=json.dumps({"group_id": "2255", "requested_count": 2}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="203.0.113.10",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed"])
        self.assertFalse(response.json()["queued"])
        self.assertFalse(response.json()["serialized"])
        self.assertTrue(response.json()["lease_id"].startswith("direct-"))
        self.assertFalse(ProfileCreateLease.objects.exists())
        self.assertFalse(ProfileCreateQueue.objects.exists())

    def test_proxy_job_returns_per_line_socks5_protocol(self):
        country = ProxyCountryFile(
            provider=self.provider,
            country_code="CA",
            country_name="Canada",
        )
        country.set_content("socks5://user:pass@proxy.example:1080\n")
        country.save()
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "CA", "count": 1}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 201)
        proxy = response.json()["job"]["proxies"][0]
        self.assertEqual(proxy["protocol"], "socks5")
        self.assertEqual(proxy["proxy"], "socks5://user:pass@proxy.example:1080")

    def test_profile_domain_batch_is_sanitized_idempotent_and_filterable(self):
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }
        payload = {
            "session_id": "session-123",
            "group_id": "2255",
            "profile_name": "1115_sys_1_1",
            "profile_id": "profile-1",
            "browser_id": "1217093",
            "session_started_at": "2026-08-02T13:00:00Z",
            "session_ended_at": "2026-08-02T13:20:00Z",
            "domains": [
                {
                    "domain": "www.Example.Domain.com",
                    "first_visited_at": "2026-08-02T13:01:00Z",
                    "last_visited_at": "2026-08-02T13:02:00Z",
                    "visit_count": 2,
                },
                {
                    "domain": "ipapi.co",
                    "first_visited_at": "2026-08-02T13:00:10Z",
                    "last_visited_at": "2026-08-02T13:00:10Z",
                    "visit_count": 1,
                },
            ],
        }
        response = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["accepted"], 2)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)
        row = ProfileDomainActivity.objects.get(domain="www.example.domain.com")
        self.assertEqual(row.profile_id, "profile-1")
        self.assertEqual(row.visit_count, 2)

        repeated = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json()["updated"], 2)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)

        payload["domains"] = [{
            "domain": "https://example.com/private?token=secret",
            "first_visited_at": "2026-08-02T13:01:00Z",
            "last_visited_at": "2026-08-02T13:01:00Z",
            "visit_count": 1,
        }]
        rejected = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)

    def test_bad_token_is_denied(self):
        response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION="Bearer invalid",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        CLOUDFLARE_ORIGIN_SECRET="test-origin-secret",
    )
    def test_verified_cloudflare_client_ip_has_priority(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="100.64.0.12",
            HTTP_X_TUBELIGHT_ORIGIN_SECRET="test-origin-secret",
            HTTP_CF_CONNECTING_IP="203.0.113.10",
            HTTP_X_REAL_IP="100.64.0.12",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ipv4"], "203.0.113.10")

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        CLOUDFLARE_ORIGIN_SECRET="test-origin-secret",
    )
    def test_spoofed_cloudflare_ip_without_origin_secret_is_rejected(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="100.64.0.12",
            HTTP_CF_CONNECTING_IP="203.0.113.10",
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_railway_real_ip_is_used(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_REAL_IP="203.0.113.10",
            HTTP_X_FORWARDED_FOR="10.0.0.3",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ipv4"], "203.0.113.10")

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_render_forwarded_first_ip_is_used(self):
        response = self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps(
                {"reported_ipv4": "203.0.113.10", "device_id": "device-one"}
            ),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR="203.0.113.10, 10.0.0.2",
        )
        self.assertEqual(response.status_code, 200)

    def test_openapi_schema_and_swagger_docs(self):
        schema_response = self.client.get(reverse("control:openapi-schema"))
        self.assertEqual(schema_response.status_code, 200)
        self.assertEqual(schema_response.json()["openapi"], "3.1.0")
        self.assertIn("/api/v1/bootstrap/", schema_response.json()["paths"])
        self.assertIn(
            "/api/v1/proxy-exit-claims/",
            schema_response.json()["paths"],
        )
        claim_schema = schema_response.json()["components"]["schemas"][
            "ExitIPClaimRequest"
        ]
        self.assertEqual(
            claim_schema["properties"]["action"]["enum"],
            ["check", "claim"],
        )

        docs_response = self.client.get(reverse("control:swagger-docs"))
        self.assertEqual(docs_response.status_code, 200)
        self.assertContains(docs_response, "SwaggerUIBundle")


class ProxyExitIPCooldownConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="Concurrent cooldown", version=1)
        self.bundle.set_payload({})
        self.bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="Concurrent client",
            ipv4="203.0.113.80",
            device_id="concurrent-device",
            office_name="Concurrent office",
            system_number="1",
            config_bundle=self.bundle,
        )
        self.job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P1",
            country_code="US",
        )
        self.reservations = [
            ProxyReservation.objects.create(
                client=self.client_access,
                job=self.job,
                provider_code="P1",
                country_code="US",
                proxy_fingerprint=f"concurrent-reservation-{number}",
            )
            for number in range(2)
        ]

    @skipUnlessDBFeature("has_select_for_update")
    @override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
    def test_concurrent_first_claim_has_exactly_one_winner(self):
        barrier = Barrier(2)
        result_lock = Lock()
        results = []
        errors = []
        claimed_at = timezone.now()

        def worker(reservation_id):
            close_old_connections()
            try:
                client = ClientAccess.objects.get(pk=self.client_access.pk)
                reservation = ProxyReservation.objects.select_related("job").get(
                    pk=reservation_id
                )
                barrier.wait(timeout=10)
                result = claim_exit_ip(
                    client=client,
                    provider_code="P1",
                    exit_ip="198.51.100.81",
                    job=reservation.job,
                    reservation=reservation,
                    now=claimed_at,
                )
                with result_lock:
                    results.append(result.claimed)
            except BaseException as exc:  # surfaced by the main test thread
                with result_lock:
                    errors.append(exc)
            finally:
                close_old_connections()

        threads = [
            Thread(target=worker, args=(reservation.pk,))
            for reservation in self.reservations
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertFalse(errors)
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(ProxyExitIPCooldown.objects.count(), 1)


class ProxyPoolTaskTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="Pool config", version=1)
        self.bundle.set_payload(
            {
                "P2_API_USERNAME": "proxy-user",
                "P2_API_PASSWORD": "proxy-password",
                "P2_PROTOCOL": "socks5",
                "P2_ACCOUNT_EMAIL": "pool-account@example.test",
            }
        )
        self.bundle.save()
        self.p2_account_key = p2_geo_account_key(
            "pool-account@example.test"
        )
        self.client_access = ClientAccess.objects.create(
            name="Pool device",
            ipv4="203.0.113.70",
            device_id="pool-device",
            office_name="Pool office",
            system_number="1",
            config_bundle=self.bundle,
        )
        self.provider = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        self.country = ProxyCountryFile(
            provider=self.provider,
            country_code="US",
            country_name="United States",
        )
        self.country.set_content("")
        self.country.save()

    def test_configured_country_targets_are_created_before_app_requests(self):
        created, configured = ensure_pool_targets(target_count=5, replenish_below=2)

        self.assertGreaterEqual(created, 249)
        self.assertEqual(configured, created)
        self.assertEqual(
            ProxyCountryFile.objects.filter(provider__code="P2").count(),
            249,
        )
        target = ProxyPoolTarget.objects.get(provider_code="P2", country_code="US")
        self.assertEqual(target.provider_code, "P2")
        self.assertEqual(target.country_code, "US")
        self.assertEqual(target.target_count, 5)
        self.assertEqual(target.replenish_below, 2)

    def test_p1_vps_environment_credentials_create_global_and_state_targets(self):
        with mock.patch.dict(
            "os.environ",
            {
                "NIMBLE_ACCOUNT_NAME": "account",
                "NIMBLE_PIPELINE_NAME": "pipeline",
                "NIMBLE_PIPELINE_PASSWORD": "password",
            },
            clear=False,
        ):
            ensure_pool_targets(
                target_count=5,
                replenish_below=2,
                include_regions=True,
            )

        self.assertEqual(
            ProxyPoolTarget.objects.filter(provider_code="P1", region="").count(),
            249,
        )
        self.assertTrue(
            ProxyPoolTarget.objects.filter(
                provider_code="P1", country_code="US", region="CA"
            ).exists()
        )
        self.assertFalse(
            ProxyPoolTarget.objects.filter(provider_code="P3", region__gt="").exists()
        )

    def test_p2_generation_uses_country_session_and_explicit_protocol(self):
        lines = _generate(
            "P2",
            "US",
            "",
            "",
            2,
            self.bundle.get_payload(),
        )

        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("socks5://"))
        self.assertIn("_c_US_s_", lines[0])
        self.assertTrue(lines[0].endswith("@pool.infatica.io:10000"))
        self.assertTrue(lines[1].endswith("@pool.infatica.io:10001"))

    def test_p2_live_city_catalog_is_shared_and_stale_rows_are_disabled(self):
        other_account_key = p2_geo_account_key("other-pool@example.test")
        stale = ProxyCityCatalog.objects.create(
            provider=self.provider,
            account_key=self.p2_account_key,
            country_code="US",
            region_code="1906",
            city_name="Old City",
            source="infatica-live",
        )
        other = ProxyCityCatalog.objects.create(
            provider=self.provider,
            account_key=other_account_key,
            country_code="US",
            region_code="1906",
            city_name="Other Account City",
            source="infatica-live",
        )
        specs = {
            ("US", "1906", "New York"): ("city", 10, 2),
            ("US", "1906", "Albany"): ("city", 10, 2),
            ("US", "1906", ""): ("state", 50, 10),
        }

        changed, disabled = _sync_city_catalog(
            self.p2_account_key, specs, ["US"]
        )

        self.assertEqual(changed, 2)
        self.assertEqual(disabled, 1)
        self.assertEqual(
            set(
                ProxyCityCatalog.objects.filter(
                    provider=self.provider,
                    account_key=self.p2_account_key,
                    country_code="US",
                    active=True,
                ).values_list("city_name", flat=True)
            ),
            {"Albany", "New York"},
        )
        stale.refresh_from_db()
        self.assertFalse(stale.active)
        other.refresh_from_db()
        self.assertTrue(other.active)

    def test_p2_catalog_only_syncs_multiple_geo_accounts_in_one_run(self):
        first_payload = self.bundle.get_payload()
        first_payload["P2_ACCOUNT_PASSWORD"] = "geo-password-a"
        self.bundle.set_payload(first_payload)
        self.bundle.save()
        second_bundle = ConfigBundle(name="Pool config B", version=1)
        second_bundle.set_payload({
            "P2_API_USERNAME": "proxy-user-b",
            "P2_API_PASSWORD": "proxy-password-b",
            "P2_PROTOCOL": "socks5",
            "P2_ACCOUNT_EMAIL": "pool-b@example.test",
            "P2_ACCOUNT_PASSWORD": "geo-password-b",
        })
        second_bundle.save()
        ClientAccess.objects.create(
            name="Pool device B",
            ipv4="203.0.113.71",
            device_id="pool-device-b",
            office_name="Pool office B",
            system_number="1",
            config_bundle=second_bundle,
        )

        def live_specs(*, email, password, countries, counts, thresholds):
            del password, counts, thresholds
            if email == "pool-account@example.test":
                region_code, region_name, city = "1906", "New York", "Albany"
            else:
                region_code, region_name, city = "1912", "Massachusetts", "Boston"
            specs = {
                ("US", "", ""): ("country", 1000, 200),
                ("US", region_code, ""): ("state", 50, 10),
                ("US", region_code, city): ("city", 10, 2),
            }
            summary = {
                "nodes_seen": 1,
                "states": 1,
                "cities": 1,
                "skipped_without_numeric_region": 0,
                "skipped_long_city": 0,
            }
            return specs, {"US": {region_code: region_name}}, summary

        output = io.StringIO()
        with mock.patch(
            "control.management.commands.prefill_p2_geo_pools._live_specs",
            side_effect=live_specs,
        ) as loader:
            call_command(
                "prefill_p2_geo_pools",
                "--office", "Pool office",
                "--office", "Pool office B",
                "--country", "US",
                "--catalog-only",
                stdout=output,
            )

        self.assertEqual(loader.call_count, 2)
        self.assertIn("accounts=2", output.getvalue())
        self.assertIn("CATALOG_DONE", output.getvalue())
        first_key = p2_geo_account_key("pool-account@example.test")
        second_key = p2_geo_account_key("pool-b@example.test")
        self.assertEqual(
            set(
                ProxyCityCatalog.objects.filter(
                    account_key=first_key,
                    active=True,
                ).values_list("city_name", flat=True)
            ),
            {"Albany"},
        )
        self.assertEqual(
            set(
                ProxyCityCatalog.objects.filter(
                    account_key=second_key,
                    active=True,
                ).values_list("city_name", flat=True)
            ),
            {"Boston"},
        )
        self.assertFalse(ProxyPoolTarget.objects.filter(city__gt="").exists())

    def test_p2_generation_keeps_numeric_state_and_city_targeting(self):
        line = _generate(
            "P2",
            "US",
            "1906",
            "New York",
            1,
            self.bundle.get_payload(),
        )[0]

        username = unquote(urlsplit(line).username)
        self.assertIn("_c_US_sd_1906_city_New-York_s_", username)

    def test_p4_generation_uses_configured_endpoint_and_sticky_state_session(self):
        config = {
            "P4_PROXY_HOST": "proxy.example.test",
            "P4_PROXY_PORT": "17521",
            "P4_PROXY_USERNAME": "office_subuser",
            "P4_PROXY_PASSWORD": "proxy-password",
            "P4_STICKY_MINUTES": "60",
        }

        self.assertTrue(provider_is_configured("P4", config))
        lines = _generate("P4", "US", "Colorado", "New York", 2, config)

        self.assertEqual(len(lines), 2)
        first = urlsplit(lines[0])
        second = urlsplit(lines[1])
        self.assertEqual(first.scheme, "http")
        self.assertEqual(first.hostname, "proxy.example.test")
        self.assertEqual(first.port, 17521)
        self.assertNotEqual(unquote(first.username), unquote(second.username))
        self.assertNotEqual(lines[0], lines[1])
        self.assertTrue(
            unquote(first.username).startswith(
                "office_subuser-country-us-st-colorado-sst-60-ssid-"
            )
        )
        self.assertNotIn("-city-", unquote(first.username))

    def test_p4_catalog_exposes_countries_and_states_without_city_data(self):
        ensure_global_country_catalog()
        ensure_p4_region_catalog()

        self.assertTrue(
            ProxyCountryFile.objects.filter(provider__code="P4", country_code="US").exists()
        )
        region = ProxyRegionCatalog.objects.get(
            provider__code="P4", country_code="US", region_code="colorado"
        )
        self.assertEqual(region.region_name, "Colorado")

    def test_refill_fills_target_and_progressively_completes_waiting_job(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            target_count=5,
            replenish_below=2,
        )
        job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P2",
            country_code="US",
            requested_count=3,
            status="waiting_generation",
        )

        created = refill_proxy_pool.run(target.pk)

        job.refresh_from_db()
        self.assertEqual(created, 5)
        self.assertEqual(job.status, "ready")
        self.assertEqual(job.ready_count, 3)
        self.assertEqual(job.reservations.count(), 3)
        self.assertEqual(target.entries.filter(state="available").count(), 2)

        second = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P2",
            country_code="US",
            requested_count=2,
            status="queued",
        )
        issued = reserve_pool_proxies(
            client=self.client_access,
            job=second,
            provider_code="P2",
            country_code="US",
        )
        self.assertEqual(len(issued), 2)
        self.assertEqual(target.entries.filter(state="available").count(), 0)

        self.assertEqual(refill_proxy_pool.run(target.pk), 5)
        self.assertEqual(target.entries.filter(state="available").count(), 5)

    def test_refill_ignores_a_stale_message_for_a_deleted_target(self):
        self.assertEqual(refill_proxy_pool.run(999999999), 0)

    def test_only_one_outstanding_refill_is_queued_per_target(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            target_count=5,
            replenish_below=2,
        )

        with mock.patch("control.tasks.refill_proxy_pool.delay") as delay:
            self.assertTrue(queue_refill_proxy_pool(target.pk))
            self.assertFalse(queue_refill_proxy_pool(target.pk))

        delay.assert_called_once_with(target.pk)
        target.refresh_from_db()
        self.assertTrue(target.refill_pending)
        self.assertIsNotNone(target.refill_requested_at)

        target.refill_requested_at = timezone.now() - timedelta(minutes=16)
        target.save(update_fields=("refill_requested_at",))
        with mock.patch("control.tasks.refill_proxy_pool.delay") as stale_delay:
            self.assertTrue(queue_refill_proxy_pool(target.pk))
        stale_delay.assert_called_once_with(target.pk)

        self.assertEqual(refill_proxy_pool.run(target.pk), 5)
        target.refresh_from_db()
        self.assertFalse(target.refill_pending)
        self.assertIsNone(target.refill_requested_at)

    def test_refill_claim_is_released_when_enqueue_fails(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
        )
        with mock.patch(
            "control.tasks.refill_proxy_pool.delay",
            side_effect=RuntimeError("broker"),
        ):
            self.assertFalse(queue_refill_proxy_pool(target.pk))
        target.refresh_from_db()
        self.assertFalse(target.refill_pending)
        self.assertIsNone(target.refill_requested_at)

    def test_office_pool_command_queues_every_assigned_bundle(self):
        first_payload = self.bundle.get_payload()
        first_payload.update(
            {
                "NIMBLE_ACCOUNT_NAME": "account-one",
                "NIMBLE_PIPELINE_NAME": "pipeline-one",
                "NIMBLE_PIPELINE_PASSWORD": "password-one",
            }
        )
        self.bundle.set_payload(first_payload)
        self.bundle.save()
        second_bundle = ConfigBundle(name="Pool config 2", version=1)
        second_bundle.set_payload(
            {
                "NIMBLE_ACCOUNT_NAME": "account-two",
                "NIMBLE_PIPELINE_NAME": "pipeline-two",
                "NIMBLE_PIPELINE_PASSWORD": "password-two",
            }
        )
        second_bundle.save()
        ClientAccess.objects.create(
            name="Pool device 2",
            ipv4="203.0.113.71",
            device_id="pool-device-two",
            office_name="POOL OFFICE",
            system_number="2",
            config_bundle=second_bundle,
        )
        output = io.StringIO()
        with mock.patch(
            "control.tasks.refill_proxy_pool.delay"
        ) as delay:
            call_command(
                "queue_office_proxy_pools",
                "--office",
                "Pool office",
                "--provider",
                "P1",
                "--country",
                "US",
                "--country",
                "GB",
                stdout=output,
            )

        self.assertEqual(
            ProxyPoolTarget.objects.filter(provider_code="P1").count(),
            4,
        )
        self.assertEqual(delay.call_count, 4)
        self.assertIn("Unique assigned bundles: 2", output.getvalue())


class StaffPanelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="panel-admin",
            email="panel@example.com",
            password="StrongPanelPassword123!",
        )
        self.bundle = ConfigBundle.objects.create(
            name="Panel config",
            browser_group_id="701",
            browser_group_name="Testing",
        )
        self.bundle.set_payload(
            {
                "NIMBLE_ACCOUNT_NAME": "account",
                "NIMBLE_PIPELINE_NAME": "pipeline",
                "NIMBLE_PIPELINE_PASSWORD": "password",
            }
        )
        self.bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="North device 1",
            ipv4="203.0.113.40",
            device_id="device-panel-one",
            office_name="North",
            system_number="1",
            profile_name="North One",
            config_bundle=self.bundle,
            last_seen_at=timezone.now(),
        )
        now = timezone.now()
        self.activity = ProfileDomainActivity.objects.create(
            client=self.client_access,
            session_id="session-panel-1",
            group_id="701",
            profile_name="North One",
            profile_id="profile-panel-1",
            browser_id="991",
            domain="www.example.com",
            first_visited_at=now - timedelta(minutes=12),
            last_visited_at=now - timedelta(minutes=2),
            visit_count=3,
            session_started_at=now - timedelta(minutes=15),
            session_ended_at=now,
        )
        ProfileDomainActivity.objects.create(
            client=self.client_access,
            session_id="session-panel-1",
            group_id="701",
            profile_name="North One",
            profile_id="profile-panel-1",
            browser_id="991",
            domain="docs.example.com",
            first_visited_at=now - timedelta(minutes=8),
            last_visited_at=now - timedelta(minutes=4),
            visit_count=2,
            session_started_at=now - timedelta(minutes=15),
            session_ended_at=now,
        )

    def login(self):
        self.client.force_login(self.user)

    def test_panel_uses_existing_admin_authentication(self):
        response = self.client.get(reverse("control:panel"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("admin:login"), response["Location"])

        self.login()
        response = self.client.get(reverse("control:panel"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Automation Control Center")
        self.assertContains(response, "Domain activity")

    def test_overview_and_every_sidebar_resource_are_api_backed(self):
        self.login()
        overview = self.client.get(reverse("control:panel-overview-api"))
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["cards"]["active_devices"], 1)
        self.assertEqual(overview.json()["cards"]["domain_visits_24h"], 5)

        resources = (
            "devices", "configurations", "groups", "providers",
            "proxy-catalog", "extensions", "proxy-pools", "proxy-inventory",
            "proxy-jobs", "reservations", "profile-activity", "access-audit",
        )
        for resource in resources:
            with self.subTest(resource=resource):
                response = self.client.get(
                    reverse("control:panel-resource-api", args=(resource,))
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn("rows", response.json())
                self.assertIn("columns", response.json())

    def test_super_admin_can_generate_provider_country_for_every_office_bundle(self):
        second_bundle = ConfigBundle.objects.create(
            name="Panel config 2",
            browser_group_id="702",
            browser_group_name="Testing 2",
        )
        second_bundle.set_payload(self.bundle.get_payload())
        second_bundle.save()
        ClientAccess.objects.create(
            name="North device 2",
            ipv4="203.0.113.41",
            device_id="device-panel-two",
            office_name="North",
            system_number="2",
            profile_name="North Two",
            config_bundle=second_bundle,
        )
        self.login()
        url = reverse("control:panel-resource-api", args=("proxy-pools",))
        with mock.patch(
            "control.panel_resources.queue_refill_proxy_pool",
            return_value=True,
        ) as queue_refill:
            response = self.client.post(
                url,
                data=json.dumps(
                    {
                        "action": "generate_office",
                        "office": "North",
                        "provider": "P1",
                        "country": "GB",
                        "target_count": 1000,
                    }
                ),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertEqual(result["bundles_found"], 2)
        self.assertEqual(result["queued"], 2)
        self.assertEqual(
            ProxyPoolTarget.objects.filter(
                provider_code="P1", country_code="GB"
            ).count(),
            2,
        )
        self.assertEqual(queue_refill.call_count, 2)

    def test_access_audit_uses_cached_cursor_pages_without_exact_count(self):
        for index in range(12):
            BootstrapAudit.objects.create(
                client=self.client_access,
                observed_ip="203.0.113.40",
                reported_ip="203.0.113.40",
                device_id=f"audit-device-{index:02d}",
                allowed=index % 2 == 0,
                reason="allowed" if index % 2 == 0 else "not-whitelisted",
                app_version="1.7.29",
            )
        self.login()
        url = reverse("control:panel-resource-api", args=("access-audit",))
        first = self.client.get(url, {"page_size": 10})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first["X-Panel-Cache"], "MISS")
        payload = first.json()
        self.assertEqual(len(payload["rows"]), 10)
        self.assertIsNone(payload["pagination"]["total"])
        self.assertTrue(payload["pagination"]["has_next"])

        cached = self.client.get(url, {"page_size": 10})
        self.assertEqual(cached["X-Panel-Cache"], "HIT")
        second = self.client.get(
            url,
            {
                "page_size": 10,
                "cursor": payload["pagination"]["next_cursor"],
            },
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.json()["rows"]), 2)

    def test_access_audit_can_grant_an_existing_device_additional_ip(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="198.51.100.90",
            reported_ip="198.51.100.90",
            device_id=self.client_access.device_id,
            allowed=False,
            reason="not-whitelisted",
            app_version="1.7.29",
        )
        self.login()
        response = self.client.post(
            reverse("control:panel-resource-api", args=("access-audit",)),
            data=json.dumps(
                {
                    "action": "grant_access",
                    "audit_id": audit.pk,
                    "ipv4": "198.51.100.90",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertTrue(
            ClientAccessIP.objects.filter(
                client=self.client_access,
                ipv4="198.51.100.90",
                active=True,
            ).exists()
        )
        audit.refresh_from_db()
        self.assertEqual(audit.client, self.client_access)

    def test_access_audit_can_create_a_new_client(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="198.51.100.91",
            reported_ip="198.51.100.91",
            device_id="new-audit-device",
            allowed=False,
            reason="not-whitelisted",
            app_version="1.7.29",
        )
        self.login()
        response = self.client.post(
            reverse("control:panel-resource-api", args=("access-audit",)),
            data=json.dumps(
                {
                    "action": "grant_access",
                    "audit_id": audit.pk,
                    "ipv4": "198.51.100.91",
                    "name": "New audit device",
                    "office": "North",
                    "system_number": "2",
                    "profile_name": "North Two",
                    "config_bundle_id": self.bundle.pk,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        created = ClientAccess.objects.get(device_id="new-audit-device")
        self.assertEqual(created.ipv4, "198.51.100.91")
        self.assertEqual(created.config_bundle, self.bundle)

    def test_domain_activity_filters_detail_and_csv_are_precise(self):
        self.login()
        response = self.client.get(
            reverse("control:panel-domain-activity-api"),
            {"range": "30d", "office": "North", "domain": "www.example"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["metrics"]["visits"], 3)
        self.assertEqual(payload["metrics"]["unique_domains"], 1)
        self.assertEqual(payload["rows"][0]["device_id"], "device-panel-one")
        self.assertEqual(payload["rows"][0]["profile_id"], "profile-panel-1")
        self.assertEqual(payload["rows"][0]["group_id"], "701")

        detail = self.client.get(
            reverse("control:panel-domain-activity-detail-api", args=(self.activity.pk,))
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.json()["session_domains"]), 2)
        self.assertEqual(detail.json()["activity"]["ipv4"], "203.0.113.40")

        export = self.client.get(
            reverse("control:panel-domain-activity-export"),
            {"range": "30d", "office": "North"},
        )
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export["Content-Type"], "text/csv; charset=utf-8")
        exported = export.content.decode("utf-8")
        self.assertIn("www.example.com", exported)
        self.assertIn("device-panel-one", exported)

    def test_suspicious_activity_uses_active_monitored_domains(self):
        MonitoredDomain.objects.create(domain="www.example.com", label="Example monitor")
        self.login()
        response = self.client.get(
            reverse("control:panel-suspicious-activity-api"),
            {"range": "30d"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["metrics"]["visits"], 3)
        self.assertEqual(payload["rows"][0]["domain"], "www.example.com")

    def test_office_ip_whitelist_page_and_api_add_only_additional_addresses(self):
        second = ClientAccess.objects.create(
            name="North device 2",
            ipv4="203.0.113.41",
            device_id="device-panel-two",
            office_name="North",
            system_number="2",
            config_bundle=self.bundle,
        )
        primary_match = ClientAccess.objects.create(
            name="North device 3",
            ipv4="198.51.100.90",
            device_id="device-panel-three",
            office_name="North",
            system_number="3",
            config_bundle=self.bundle,
        )
        inactive = ClientAccess.objects.create(
            name="North inactive",
            ipv4="203.0.113.42",
            device_id="device-panel-inactive",
            office_name="North",
            system_number="4",
            config_bundle=self.bundle,
            active=False,
        )
        ClientAccessIP.objects.create(
            client=self.client_access,
            ipv4="198.51.100.90",
            active=False,
        )
        self.login()

        page = self.client.get(reverse("control:panel-office-ip-whitelist"))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Office IP whitelist")
        self.assertContains(page, "North")

        response = self.client.post(
            reverse("control:panel-office-ip-whitelist-api"),
            data=json.dumps({"office": "north", "ipv4": "198.51.100.90"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertEqual(result["devices"], 3)
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["reactivated"], 1)
        self.assertEqual(result["primary_ip_skipped"], 1)
        self.assertEqual(result["existing_additional_skipped"], 0)
        self.assertEqual(str(self.client_access.ipv4), "203.0.113.40")
        self.assertTrue(
            ClientAccessIP.objects.filter(
                client=self.client_access, ipv4="198.51.100.90", active=True
            ).exists()
        )
        self.assertTrue(
            ClientAccessIP.objects.filter(
                client=second, ipv4="198.51.100.90", active=True
            ).exists()
        )
        self.assertFalse(
            ClientAccessIP.objects.filter(
                client=primary_match, ipv4="198.51.100.90"
            ).exists()
        )
        self.assertFalse(
            ClientAccessIP.objects.filter(
                client=inactive, ipv4="198.51.100.90"
            ).exists()
        )

    def test_office_ip_whitelist_api_rejects_invalid_ip(self):
        self.login()
        response = self.client.post(
            reverse("control:panel-office-ip-whitelist-api"),
            data=json.dumps({"office": "North", "ipv4": "not-an-ip"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    TRUST_APP_REPORTED_IPV4=False,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
)
class DesktopReleaseApiTests(TestCase):
    def setUp(self):
        self._media_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._media_directory.cleanup)
        self._media_settings = override_settings(
            MEDIA_ROOT=self._media_directory.name,
            DESKTOP_RELEASE_ROOT=(
                self._media_directory.name + "/private-desktop-releases"
            ),
        )
        self._media_settings.enable()
        self.addCleanup(self._media_settings.disable)

        self.private_key = Ed25519PrivateKey.generate()
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(public_bytes).decode("ascii")
        self._key_patch = mock.patch(
            "control.release_updates.DESKTOP_RELEASE_PUBLIC_KEY_B64",
            self.public_key_b64,
        )
        self._key_patch.start()
        self.addCleanup(self._key_patch.stop)

        self.bundle = ConfigBundle(name="Release test bundle", version=1)
        self.bundle.set_payload({"APP_API_KEY": "test-key"})
        self.bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="Release test device",
            ipv4="203.0.113.80",
            device_id="release-device",
            office_name="Release Office",
            system_number="8",
            config_bundle=self.bundle,
            release_channel=ClientAccess.RELEASE_CHANNEL_PUBLIC,
        )

    def bootstrap(
        self,
        *,
        app_build=0,
        app_channel="public",
        update_protocol=None,
    ):
        body = {
            "reported_ipv4": "203.0.113.80",
            "app_version": "1.7.35",
            "device_id": "release-device",
        }
        if update_protocol is not None:
            body.update(
                {
                    "app_build": app_build,
                    "app_channel": app_channel,
                    "update_protocol": update_protocol,
                }
            )
        return self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps(body),
            content_type="application/json",
            REMOTE_ADDR="203.0.113.80",
        )

    def create_release(
        self,
        *,
        build_number,
        version=None,
        channel=DesktopRelease.CHANNEL_PUBLIC,
        mode=DesktopRelease.MODE_OPTIONAL,
        target_offices=None,
        target_device_ids=None,
        publish=True,
        payload=None,
    ):
        raw = payload or f"MZquest-release-{build_number}".encode("ascii")
        release = DesktopRelease(
            channel=channel,
            version=version or f"1.7.{build_number}",
            build_number=build_number,
            mode=mode,
            target_offices=target_offices or [],
            target_device_ids=target_device_ids or [],
            artifact=SimpleUploadedFile(
                f"Quest-Automation-{build_number}.exe",
                raw,
                content_type="application/vnd.microsoft.portable-executable",
            ),
        )
        release.full_clean()
        release.save()
        release.signature_b64 = base64.b64encode(
            self.private_key.sign(canonical_release_payload(release))
        ).decode("ascii")
        release.save(update_fields=("signature_b64", "updated_at"))
        if publish:
            release.status = DesktopRelease.STATUS_PUBLISHED
            release.published_at = timezone.now()
            release.save(update_fields=("status", "published_at", "updated_at"))
        return release

    def authenticated_headers(self):
        token = self.bootstrap().json()["access_token"]
        return {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "release-device",
            "REMOTE_ADDR": "203.0.113.80",
        }

    def test_legacy_bootstrap_does_not_include_update_manifest(self):
        response = self.bootstrap()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("desktop_update", response.json())

    def test_bootstrap_uses_assigned_channel_and_requires_channel_match(self):
        public_release = self.create_release(build_number=35)
        self.create_release(
            build_number=60,
            version="1.8.60",
            channel=DesktopRelease.CHANNEL_TESTING,
        )

        mismatch = self.bootstrap(
            app_build=0,
            app_channel="testing",
            update_protocol=1,
        )
        self.assertIsNone(mismatch.json()["desktop_update"])

        response = self.bootstrap(
            app_build=0,
            app_channel="public",
            update_protocol=1,
        )
        manifest = response.json()["desktop_update"]
        self.assertEqual(manifest["id"], public_release.pk)
        self.assertEqual(manifest["channel"], "public")
        self.assertEqual(
            manifest["download_path"],
            f"/api/v1/desktop-releases/{public_release.pk}/",
        )
        self.assertEqual(manifest["product"], "quest-automation")
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["signature"], public_release.signature_b64)

    def test_bootstrap_selects_newer_applicable_release_only(self):
        applicable = self.create_release(
            build_number=40,
            target_offices=["release office"],
            target_device_ids=["release-device"],
        )
        self.create_release(
            build_number=45,
            target_offices=["Release Office"],
            target_device_ids=["another-device"],
        )
        self.create_release(
            build_number=50,
            target_offices=["Another Office"],
        )

        response = self.bootstrap(
            app_build=35,
            app_channel="public",
            update_protocol=1,
        )
        self.assertEqual(response.json()["desktop_update"]["id"], applicable.pk)

        current = self.bootstrap(
            app_build=applicable.build_number,
            app_channel="public",
            update_protocol=1,
        )
        self.assertIsNone(current.json()["desktop_update"])

    def test_invalid_signature_is_rejected_and_skipped(self):
        valid = self.create_release(build_number=70)
        invalid = self.create_release(build_number=80, publish=False)
        invalid.signature_b64 = base64.b64encode(b"x" * 64).decode("ascii")
        invalid.save(update_fields=("signature_b64", "updated_at"))
        with self.assertRaises(ValidationError):
            verify_release_signature(invalid)
        DesktopRelease.objects.filter(pk=invalid.pk).update(
            status=DesktopRelease.STATUS_PUBLISHED,
            published_at=timezone.now(),
        )

        response = self.bootstrap(
            app_build=0,
            app_channel="public",
            update_protocol=1,
        )
        self.assertEqual(response.json()["desktop_update"]["id"], valid.pk)

    def test_authenticated_scoped_download_streams_exact_signed_exe(self):
        raw = b"MZexact-signed-release-bytes"
        release = self.create_release(
            build_number=90,
            mode=DesktopRelease.MODE_MANDATORY,
            target_offices=["Release Office"],
            target_device_ids=["release-device"],
            payload=raw,
        )
        with self.assertRaises(ValueError):
            _ = release.artifact.url
        response = self.client.get(
            reverse("control:desktop-release-download", args=(release.pk,)),
            **self.authenticated_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), raw)
        self.assertEqual(response["X-Content-SHA256"], release.artifact_sha256)
        self.assertEqual(int(response["Content-Length"]), len(raw))
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn("no-store", response["Cache-Control"])

    def test_saved_draft_form_renders_without_exposing_private_file_url(self):
        release = self.create_release(build_number=95, publish=False)
        html = DesktopReleaseForm(instance=release).as_p()
        self.assertIn('type="file"', html)
        self.assertNotIn("/media/", html)
        self.assertNotIn(release.artifact.name, html)

    def test_release_status_transitions_cannot_bypass_publish_validation(self):
        with self.assertRaises(ValidationError):
            DesktopRelease(
                channel=DesktopRelease.CHANNEL_PUBLIC,
                version="1.7.103",
                build_number=103,
                status=DesktopRelease.STATUS_REVOKED,
                artifact=SimpleUploadedFile("new-revoked.exe", b"MZinvalid-state"),
            ).save()

        draft = self.create_release(build_number=104, publish=False)
        draft.status = DesktopRelease.STATUS_REVOKED
        with self.assertRaises(ValidationError):
            draft.save(update_fields=("status", "updated_at"))

    def test_release_version_rejects_unicode_digits_and_trailing_newline(self):
        for version in ("١.٢.٣", "1.7.105\n"):
            with self.subTest(version=repr(version)), self.assertRaises(
                ValidationError
            ):
                DesktopRelease(
                    channel=DesktopRelease.CHANNEL_PUBLIC,
                    version=version,
                    build_number=105,
                    artifact=SimpleUploadedFile("invalid-version.exe", b"MZversion"),
                ).save()

    def test_replacing_and_deleting_draft_cleans_private_artifacts(self):
        draft = self.create_release(build_number=106, publish=False)
        storage = draft.artifact.storage
        original_name = draft.artifact.name
        self.assertTrue(storage.exists(original_name))

        draft.artifact = SimpleUploadedFile(
            "replacement.exe",
            b"MZreplacement-release",
        )
        with self.captureOnCommitCallbacks(execute=True):
            draft.save()
        replacement_name = draft.artifact.name
        self.assertNotEqual(original_name, replacement_name)
        self.assertFalse(storage.exists(original_name))
        self.assertTrue(storage.exists(replacement_name))

        with self.captureOnCommitCallbacks(execute=True):
            draft.delete()
        self.assertFalse(storage.exists(replacement_name))

    def test_admin_can_reopen_draft_and_published_release_without_file_url(self):
        admin_user = get_user_model().objects.create_superuser(
            username="release-admin",
            email="release-admin@example.com",
            password="test-admin-password",
        )
        draft = self.create_release(build_number=101, publish=False)
        published = self.create_release(build_number=102)
        self.client.force_login(admin_user)

        for release in (draft, published):
            response = self.client.get(
                reverse("admin:control_desktoprelease_change", args=(release.pk,)),
                secure=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, release.original_filename)
            self.assertNotContains(response, "/media/")
            self.assertNotContains(response, release.artifact.name)

    def test_download_denies_wrong_channel_scope_and_missing_auth(self):
        release = self.create_release(build_number=100)
        url = reverse("control:desktop-release-download", args=(release.pk,))

        missing_auth = self.client.get(url, REMOTE_ADDR="203.0.113.80")
        self.assertEqual(missing_auth.status_code, 403)

        headers = self.authenticated_headers()
        release.target_offices = ["Another Office"]
        release.save(update_fields=("target_offices", "updated_at"))
        wrong_scope = self.client.get(url, **headers)
        self.assertEqual(wrong_scope.status_code, 403)

        release.target_offices = []
        release.save(update_fields=("target_offices", "updated_at"))
        self.client_access.release_channel = ClientAccess.RELEASE_CHANNEL_TESTING
        self.client_access.save(update_fields=("release_channel", "updated_at"))
        wrong_channel = self.client.get(url, **headers)
        self.assertEqual(wrong_channel.status_code, 403)


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    TRUST_APP_REPORTED_IPV4=False,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
    DESKTOP_COMPONENT_MAX_BYTES=10 * 1024 * 1024,
)
class DesktopComponentReleaseApiTests(TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self._settings = override_settings(
            DESKTOP_RELEASE_ROOT=self._directory.name + "/private-releases"
        )
        self._settings.enable()
        self.addCleanup(self._settings.disable)
        self.private_key = Ed25519PrivateKey.generate()
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_patch = mock.patch(
            "control.release_updates.DESKTOP_RELEASE_PUBLIC_KEY_B64",
            base64.b64encode(public_bytes).decode("ascii"),
        )
        self._key_patch.start()
        self.addCleanup(self._key_patch.stop)
        bundle = ConfigBundle(name="Component bundle", version=1)
        bundle.set_payload({"APP_API_KEY": "component-test"})
        bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="Component device",
            ipv4="203.0.113.90",
            device_id="component-device",
            office_name="Component Office",
            system_number="9",
            config_bundle=bundle,
            release_channel=ClientAccess.RELEASE_CHANNEL_PUBLIC,
        )

    def bootstrap(self, protocol=2):
        return self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps({
                "reported_ipv4": "203.0.113.90",
                "app_version": "1.7.41",
                "app_build": 10742,
                "app_channel": "public",
                "update_protocol": protocol,
                "device_id": "component-device",
            }),
            content_type="application/json",
            REMOTE_ADDR="203.0.113.90",
        )

    def headers(self):
        token = self.bootstrap().json()["access_token"]
        return {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "component-device",
            "REMOTE_ADDR": "203.0.113.90",
        }

    def create_component(
        self,
        *,
        component,
        slot="default",
        build_number=1,
        version="1.0.0",
        metadata=None,
        target_offices=None,
        raw=None,
    ):
        raw = raw or json.dumps({"component": component}).encode("utf-8")
        suffix = "json" if component == DesktopComponentRelease.COMPONENT_CONFIG else "zip"
        if suffix == "zip" and raw[:2] != b"PK":
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("index.html", "ready")
            raw = stream.getvalue()
        release = DesktopComponentRelease(
            component=component,
            slot=slot,
            channel=DesktopComponentRelease.CHANNEL_PUBLIC,
            version=version,
            build_number=build_number,
            activation=DesktopComponentRelease.ACTIVATION_HOT,
            target_offices=target_offices or [],
            metadata=metadata or {},
            artifact=SimpleUploadedFile(
                f"{component}-{slot}.{suffix}", raw, content_type="application/octet-stream"
            ),
        )
        release.full_clean()
        release.save()
        release.signature_b64 = base64.b64encode(
            self.private_key.sign(canonical_component_payload(release))
        ).decode("ascii")
        release.save(update_fields=("signature_b64", "updated_at"))
        release.status = DesktopComponentRelease.STATUS_PUBLISHED
        release.published_at = timezone.now()
        release.save(update_fields=("status", "published_at", "updated_at"))
        return release

    def test_bootstrap_and_manifest_keep_multiple_browser_slots(self):
        config = self.create_component(
            component="config", build_number=2, version="2.0.0"
        )
        browser_140 = self.create_component(
            component="browser", slot="140", build_number=3, version="140",
            metadata={"browser_version": "140"},
        )
        browser_148 = self.create_component(
            component="browser", slot="148", build_number=4, version="148",
            metadata={"browser_version": "148"},
        )
        self.create_component(
            component="engine", build_number=9, version="9.0.0",
            target_offices=["Another Office"],
        )
        payload = self.bootstrap().json()
        rows = payload["desktop_components"]
        self.assertEqual(
            {(row["component"], row["slot"]) for row in rows},
            {("config", "default"), ("browser", "140"), ("browser", "148")},
        )
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id[config.pk]["activation"], "hot")
        self.assertEqual(by_id[browser_140.pk]["metadata"]["browser_version"], "140")
        self.assertEqual(by_id[browser_148.pk]["product"], "quest-automation")

    def test_authenticated_component_download_and_signature(self):
        raw = json.dumps({"providers": [{"id": "P3", "name": "P3"}]}).encode()
        release = self.create_component(
            component="config", build_number=10, version="10.0.0", raw=raw
        )
        verify_component_signature(release)
        manifest = self.client.get(
            reverse("control:desktop-component-manifest"), **self.headers()
        )
        self.assertEqual(manifest.status_code, 200)
        self.assertEqual(manifest.json()["components"][0]["id"], release.pk)
        response = self.client.get(
            reverse("control:desktop-component-download", args=(release.pk,)),
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), raw)
        self.assertEqual(response["X-Content-SHA256"], release.artifact_sha256)

    def test_admin_form_rejects_traversal_zip(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../outside.js", "bad")
        form = DesktopComponentReleaseForm(data={
            "component": "ui", "slot": "default", "channel": "public",
            "version": "1.0.0", "build_number": 1, "activation": "hot",
            "target_offices": "[]", "target_device_ids": "[]", "metadata": "{}",
            "signature_b64": "",
        }, files={"artifact": SimpleUploadedFile("ui.zip", stream.getvalue())})
        self.assertFalse(form.is_valid())
        self.assertIn("unsafe path", str(form.errors["artifact"]).lower())
