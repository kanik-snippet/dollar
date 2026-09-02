from __future__ import annotations

from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from .geo_catalog import ensure_global_country_catalog
from .models import (
    ClientAccess,
    ConfigBundle,
    Provider,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyRegionCatalog,
)


class PrefillP2GeoPoolsTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="P2 office bundle", version=1)
        self.bundle.set_payload(
            {
                "P2_API_USERNAME": "api-user",
                "P2_API_PASSWORD": "api-password",
                "P2_ACCOUNT_EMAIL": "geo@example.test",
                "P2_ACCOUNT_PASSWORD": "geo-password",
            }
        )
        self.bundle.save()
        ClientAccess.objects.create(
            name="P2 device",
            ipv4="203.0.113.90",
            device_id="p2-device",
            office_name="P2 Office",
            system_number="1",
            config_bundle=self.bundle,
        )

    @staticmethod
    def _geo_response(url, form):
        assert form == {
            "email": "geo@example.test",
            "password": "geo-password",
        }
        if url.endswith("geo_nodes.php"):
            return [
                [
                    {
                        "country": "US",
                        "subdivision": "California",
                        "city": "Los Angeles",
                    },
                    {
                        "country": "US",
                        "subdivision": "California",
                        "city": "San Francisco",
                    },
                    {
                        "country": "US",
                        "subdivision": "California",
                        "city": "Los Angeles",
                    },
                    {
                        "country": "US",
                        "subdivision": "Unknown Region",
                        "city": "Dropped City",
                    },
                    {
                        "country": "CA",
                        "subdivision": "Ontario",
                        "city": "Toronto",
                    },
                    {
                        "country": "GB",
                        "subdivision": "England",
                        "city": "London",
                    },
                ]
            ]
        if url.endswith("subdivision_codes.php"):
            return [
                [
                    {"subdivision": "California", "code": 1906},
                    {"subdivision": "Ontario", "code": 2011},
                    {"subdivision": "England", "code": 8261},
                ]
            ]
        raise AssertionError(f"Unexpected URL: {url}")

    @staticmethod
    def _fill_one(target_id):
        target = ProxyPoolTarget.objects.get(pk=target_id)
        if not target.entries.filter(state="available").exists():
            entry = ProxyPoolEntry(
                target=target,
                proxy_fingerprint=f"{target_id:064x}",
                state="available",
            )
            entry.set_proxy(f"socks5://user:password@p2-{target_id}.example:10000")
            entry.save()
        ProxyPoolTarget.objects.filter(pk=target_id).update(
            refill_pending=False,
            refill_requested_at=None,
        )
        return True

    @mock.patch(
        "control.management.commands.prefill_p2_geo_pools.queue_refill_proxy_pool"
    )
    @mock.patch("control.management.commands.prefill_p2_geo_pools._post_form_json")
    def test_creates_country_state_and_state_city_targets_only(
        self,
        post_form,
        queue_refill,
    ):
        post_form.side_effect = self._geo_response
        queue_refill.side_effect = self._fill_one
        stdout = StringIO()
        stderr = StringIO()
        ensure_global_country_catalog()
        stale_region = ProxyRegionCatalog.objects.create(
            provider=Provider.objects.get(code="P2"),
            country_code="US",
            region_code="9999",
            region_name="Removed Region",
            source="infatica-live",
            active=True,
        )
        stale_target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            region="9999",
            city="Removed City",
            target_count=1,
            replenish_below=0,
            active=True,
        )

        call_command(
            "prefill_p2_geo_pools",
            office=["P2 Office"],
            country=["US"],
            country_target=1,
            country_threshold=0,
            state_target=1,
            state_threshold=0,
            city_target=1,
            city_threshold=0,
            prefill_city_pools=True,
            batch_size=2,
            batch_timeout=30,
            stdout=stdout,
            stderr=stderr,
        )

        locations = set(
            ProxyPoolTarget.objects.filter(
                config_bundle=self.bundle,
                provider_code="P2",
                active=True,
            ).values_list("country_code", "region", "city")
        )
        self.assertEqual(
            locations,
            {
                ("US", "", ""),
                ("US", "1906", ""),
                ("US", "1906", "Los Angeles"),
                ("US", "1906", "San Francisco"),
            },
        )
        self.assertFalse(
            ProxyPoolTarget.objects.filter(
                config_bundle=self.bundle,
                provider_code="P2",
                region="",
                city__gt="",
            ).exists()
        )
        self.assertEqual(post_form.call_count, 2)
        self.assertEqual(queue_refill.call_count, 4)
        self.assertEqual(
            ProxyPoolEntry.objects.filter(state="available").count(),
            4,
        )
        region = ProxyRegionCatalog.objects.get(
            provider__code="P2",
            country_code="US",
            region_code="1906",
        )
        self.assertEqual(region.region_name, "California")
        self.assertEqual(region.source, "infatica-live")
        stale_target.refresh_from_db()
        # The catalog is global across accounts; per-bundle stale targets are
        # deactivated without removing another account's valid region row.
        stale_region.refresh_from_db()
        self.assertTrue(stale_region.active)
        self.assertFalse(stale_target.active)
        self.assertIn(
            "skipped live nodes without a numeric subdivision ID: 1",
            stderr.getvalue(),
        )
        self.assertIn("PREFILL_DONE targets=4/4 failures=0", stdout.getvalue())

    @mock.patch("control.management.commands.prefill_p2_geo_pools._post_form_json")
    def test_status_only_fetches_once_without_creating_or_syncing(self, post_form):
        post_form.side_effect = self._geo_response

        call_command(
            "prefill_p2_geo_pools",
            office=["P2 Office"],
            country=["UK"],
            status_only=True,
            stdout=StringIO(),
            stderr=StringIO(),
        )

        self.assertEqual(post_form.call_count, 2)
        self.assertFalse(ProxyPoolTarget.objects.exists())
        self.assertFalse(ProxyRegionCatalog.objects.exists())
