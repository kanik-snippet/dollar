from __future__ import annotations

import hashlib
import logging

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from .models import ClientAccess, ProxyInventoryAlert


logger = logging.getLogger(__name__)


def record_proxy_inventory_shortage(
    *,
    client: ClientAccess,
    provider_code: str,
    country_code: str,
    region: str,
    city: str,
    available_count: int,
    requested_count: int,
) -> ProxyInventoryAlert:
    """Record every shortage but send at most one alert per scope/cooldown."""
    now = timezone.now()
    cooldown = max(60, int(settings.PROXY_ALERT_COOLDOWN_SECONDS))
    window = int(now.timestamp()) // cooldown
    dedupe_key = hashlib.sha256(
        (
            f"{client.office_name.strip().casefold()}|{provider_code}|{country_code}|"
            f"{region}|{city}|{window}"
        ).encode("utf-8")
    ).hexdigest()
    try:
        # Isolate a concurrent duplicate insert in its own savepoint so the
        # surrounding proxy-job transaction remains usable after IntegrityError.
        with transaction.atomic():
            alert = ProxyInventoryAlert.objects.create(
                dedupe_key=dedupe_key,
                client=client,
                config_bundle=client.config_bundle,
                office_name=client.office_name,
                system_number=client.system_number,
                device_id=client.device_id,
                provider_code=provider_code,
                country_code=country_code,
                region=region,
                city=city,
                available_count=available_count,
                requested_count=requested_count,
            )
    except IntegrityError:
        alert = ProxyInventoryAlert.objects.get(dedupe_key=dedupe_key)
        ProxyInventoryAlert.objects.filter(pk=alert.pk).update(
            occurrence_count=F("occurrence_count") + 1,
            client=client,
            config_bundle=client.config_bundle,
            office_name=client.office_name,
            system_number=client.system_number,
            device_id=client.device_id,
            available_count=available_count,
            requested_count=requested_count,
            last_seen_at=now,
        )
        alert.refresh_from_db()
        return alert

    if not settings.PROXY_ALERT_ENABLED:
        alert.status = "disabled"
        alert.error = "Proxy inventory alerts are disabled in server configuration."
        alert.save(update_fields=("status", "error"))
        return alert

    def enqueue() -> None:
        from .tasks import send_proxy_inventory_alert

        try:
            send_proxy_inventory_alert.delay(alert.pk)
        except Exception as exc:
            ProxyInventoryAlert.objects.filter(pk=alert.pk).update(
                status="queue_failed",
                error=f"Alert queue unavailable: {type(exc).__name__}: {exc}"[:1000],
            )
            logger.warning("Could not queue proxy alert %s: %s", alert.pk, exc)

    transaction.on_commit(enqueue)
    return alert
