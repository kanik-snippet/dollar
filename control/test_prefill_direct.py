from django.utils import timezone
from django.test import TestCase

from .models import (
    ClientAccess,
    ConfigBundle,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyPoolTarget,
)
from .prefill import fill_targets_direct, targets_with_available_count


class DirectPrefillTests(TestCase):
    def test_fills_only_each_targets_missing_inventory(self):
        bundle = ConfigBundle(name="Direct prefill", version=1)
        bundle.set_payload({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
            "P2_PROTOCOL": "socks5",
        })
        bundle.save()
        first = ProxyPoolTarget.objects.create(
            config_bundle=bundle,
            provider_code="P2",
            country_code="US",
            region="1906",
            city="New York",
            target_count=3,
            replenish_below=1,
        )
        second = ProxyPoolTarget.objects.create(
            config_bundle=bundle,
            provider_code="P2",
            country_code="CA",
            region="1201",
            target_count=2,
            replenish_below=1,
        )
        existing = ProxyPoolEntry(target=first, proxy_fingerprint="a" * 64)
        existing.set_proxy("socks5://user:pass@example.test:10000")
        existing.save()
        targets = list(
            targets_with_available_count(
                ProxyPoolTarget.objects.filter(pk__in=(first.pk, second.pk))
                .select_related("config_bundle")
                .order_by("pk")
            )
        )

        created = fill_targets_direct(
            targets,
            target_batch_size=1,
            entry_batch_size=2,
        )

        self.assertEqual(created, 4)
        self.assertEqual(first.entries.filter(state="available").count(), 3)
        self.assertEqual(second.entries.filter(state="available").count(), 2)
        self.assertFalse(
            ProxyPoolTarget.objects.filter(
                pk__in=(first.pk, second.pk),
                refill_pending=True,
            ).exists()
        )

    def test_does_not_take_or_clear_an_existing_refill_claim(self):
        bundle = ConfigBundle(name="Claimed prefill", version=1)
        bundle.set_payload({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
        })
        bundle.save()
        claimed_at = timezone.now()
        target = ProxyPoolTarget.objects.create(
            config_bundle=bundle,
            provider_code="P2",
            country_code="US",
            target_count=2,
            replenish_below=1,
            refill_pending=True,
            refill_requested_at=claimed_at,
        )
        targets = list(
            targets_with_available_count(
                ProxyPoolTarget.objects.filter(pk=target.pk)
            )
        )

        with self.assertRaisesRegex(RuntimeError, "Another refill owns"):
            fill_targets_direct(targets)
        target.refresh_from_db()
        self.assertTrue(target.refill_pending)
        self.assertEqual(target.refill_requested_at, claimed_at)
        self.assertFalse(target.entries.exists())

    def test_fulfils_an_existing_waiting_job_after_direct_fill(self):
        bundle = ConfigBundle(name="Waiting prefill", version=1)
        bundle.set_payload({
            "P2_API_USERNAME": "proxy-user",
            "P2_API_PASSWORD": "proxy-password",
        })
        bundle.save()
        client = ClientAccess.objects.create(
            name="Waiting device",
            ipv4="203.0.113.91",
            device_id="waiting-device",
            office_name="Waiting office",
            system_number="1",
            config_bundle=bundle,
        )
        target = ProxyPoolTarget.objects.create(
            config_bundle=bundle,
            provider_code="P2",
            country_code="US",
            region="1906",
            city="New York",
            target_count=2,
            replenish_below=1,
        )
        job = ProxyGenerationJob.objects.create(
            client=client,
            provider_code="P2",
            country_code="US",
            region="1906",
            city="New York",
            submitted_count=1,
            requested_count=1,
            candidate_count=1,
            status="waiting_generation",
        )
        targets = list(
            targets_with_available_count(
                ProxyPoolTarget.objects.filter(pk=target.pk)
            )
        )

        self.assertEqual(fill_targets_direct(targets), 2)
        job.refresh_from_db()
        self.assertEqual(job.status, "ready")
        self.assertEqual(job.ready_count, 1)
        self.assertEqual(job.reservations.count(), 1)
        self.assertEqual(target.entries.filter(state="available").count(), 1)
