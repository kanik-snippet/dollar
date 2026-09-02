from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from .models import ProxyGenerationJob, ProxyPoolEntry, ProxyPoolTarget
from .proxy_jobs import fulfill_waiting_jobs, proxy_fingerprint
from .tasks import _generate


def targets_with_available_count(queryset):
    return queryset.annotate(
        available_count=Count(
            "entries",
            filter=Q(entries__state="available"),
        )
    )


def fill_targets_direct(
    targets: Sequence[ProxyPoolTarget],
    *,
    target_batch_size: int = 250,
    entry_batch_size: int = 2000,
    progress: Callable[[int, int, int], None] | None = None,
) -> int:
    """Fill pre-provisioned targets efficiently without publishing Celery jobs.

    This is intended for explicit administrator-run bulk prefill operations.
    It generates the same encrypted pool rows as ``refill_proxy_pool`` while
    batching database writes, which avoids flooding Redis with hundreds of
    thousands of tiny tasks during a full state/city rollout.
    """
    total = len(targets)
    created = 0
    configs: dict[int, dict] = {}
    target_batch_size = max(1, int(target_batch_size))
    entry_batch_size = max(1, int(entry_batch_size))

    for offset in range(0, total, target_batch_size):
        requested_batch = list(targets[offset : offset + target_batch_size])
        requested_ids = [target.pk for target in requested_batch]
        with transaction.atomic():
            batch = list(
                ProxyPoolTarget.objects.select_for_update()
                .filter(pk__in=requested_ids, active=True)
                .select_related("config_bundle")
                .order_by("pk")
            )
            target_ids = [target.pk for target in batch]
            missing_ids = set(requested_ids) - set(target_ids)
            if missing_ids:
                raise RuntimeError(
                    f"Could not lock {len(missing_ids)} active prefill target(s)."
                )

            stale_before = timezone.now() - timedelta(
                seconds=max(
                    60,
                    int(getattr(settings, "PROXY_REFILL_STALE_SECONDS", 900)),
                )
            )
            owned = [
                target
                for target in batch
                if target.refill_pending
                and target.refill_requested_at is not None
                and target.refill_requested_at > stale_before
            ]
            if owned:
                raise RuntimeError(
                    f"Another refill owns {len(owned)} prefill target(s). "
                    "Retry after it finishes."
                )

            claim_time = timezone.now()
            ProxyPoolTarget.objects.filter(pk__in=target_ids).update(
                refill_pending=True,
                refill_requested_at=claim_time,
            )
            available_by_target = {
                row["target_id"]: int(row["available_count"])
                for row in ProxyPoolEntry.objects.filter(
                    target_id__in=target_ids,
                    state="available",
                )
                .values("target_id")
                .annotate(available_count=Count("pk"))
            }
            before_available = sum(available_by_target.values())
            pending_entries: list[ProxyPoolEntry] = []
            for target in batch:
                available = available_by_target.get(target.pk, 0)
                needed = max(0, int(target.target_count) - available)
                if not needed:
                    continue
                config = configs.get(target.config_bundle_id)
                if config is None:
                    config = target.config_bundle.get_payload()
                    configs[target.config_bundle_id] = config
                for line in _generate(
                    target.provider_code,
                    target.country_code,
                    target.region,
                    target.city,
                    needed,
                    config,
                ):
                    entry = ProxyPoolEntry(
                        target=target,
                        proxy_fingerprint=proxy_fingerprint(line),
                    )
                    entry.set_proxy(line)
                    pending_entries.append(entry)
                    if len(pending_entries) >= entry_batch_size:
                        ProxyPoolEntry.objects.bulk_create(
                            pending_entries,
                            batch_size=entry_batch_size,
                            ignore_conflicts=True,
                        )
                        pending_entries.clear()
            if pending_entries:
                ProxyPoolEntry.objects.bulk_create(
                    pending_entries,
                    batch_size=entry_batch_size,
                    ignore_conflicts=True,
                )
                pending_entries.clear()
            after_available = ProxyPoolEntry.objects.filter(
                target_id__in=target_ids,
                state="available",
            ).count()
            created += max(0, after_available - before_available)

            waiting_scopes = set(
                ProxyGenerationJob.objects.filter(
                    status__in=("waiting_generation", "partial"),
                    client__config_bundle_id__in={
                        target.config_bundle_id for target in batch
                    },
                    provider_code__in={target.provider_code for target in batch},
                    country_code__in={target.country_code for target in batch},
                ).values_list(
                    "client__config_bundle_id",
                    "provider_code",
                    "country_code",
                    "region",
                    "city",
                )
            )
            for target in batch:
                if (
                    target.config_bundle_id,
                    target.provider_code,
                    target.country_code,
                    target.region,
                    target.city,
                ) in waiting_scopes:
                    fulfill_waiting_jobs(target)

            ProxyPoolTarget.objects.filter(pk__in=target_ids).update(
                refill_pending=False,
                refill_requested_at=None,
            )
        completed = min(offset + len(requested_batch), total)
        if progress is not None:
            progress(completed, total, created)
    return created
