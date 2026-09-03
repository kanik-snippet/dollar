from __future__ import annotations

import os
import logging
import re
import secrets
import urllib.parse
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from .geo_catalog import (
    ensure_global_country_catalog,
    ensure_p1_region_catalog,
    sync_provider_geography,
)
from .models import (
    ConfigBundle,
    ProxyCountryFile,
    ProxyGenerationJob,
    ProxyInventoryAlert,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyRegionCatalog,
)
from .proxy_jobs import fulfill_waiting_jobs, get_or_create_pool_target, proxy_fingerprint


DEFAULT_POOL_TARGET = 1000
DEFAULT_POOL_THRESHOLD = 200
SUPPORTED_DYNAMIC_PROVIDERS = frozenset({"P1", "P2", "P3", "P4"})
logger = logging.getLogger(__name__)


def _value(config: dict, *names: str) -> str:
    for name in names:
        value = str(config.get(name) or os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _session() -> str:
    return secrets.token_hex(8)


def _protocol(config: dict, provider: str, default: str = "http") -> str:
    value = _value(config, f"{provider}_PROTOCOL").casefold()
    return value if value in {"http", "https", "socks5"} else default


def _bounded_int(value: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _p4_location_segment(value: str) -> str:
    """Format a country/state component for the P4 proxy username."""
    normalized = re.sub(r"\s+", "_", str(value or "").strip().lower())
    return re.sub(r"[^a-z0-9_-]", "", normalized)


def _proxy_url(protocol: str, host: str, port: int, username: str, password: str) -> str:
    user = urllib.parse.quote(username, safe="")
    secret = urllib.parse.quote(password, safe="")
    return f"{protocol}://{user}:{secret}@{host}:{int(port)}"


def provider_is_configured(provider: str, config: dict) -> bool:
    provider = provider.upper()
    if provider == "P1":
        return all((
            _value(config, "NIMBLE_ACCOUNT_NAME", "P1_ACCOUNT_NAME"),
            _value(config, "NIMBLE_PIPELINE_NAME", "P1_PIPELINE_NAME"),
            _value(config, "NIMBLE_PIPELINE_PASSWORD", "P1_PIPELINE_PASSWORD"),
        ))
    if provider == "P2":
        return all((
            _value(config, "INFATICA_API_USERNAME", "P2_API_USERNAME"),
            _value(config, "INFATICA_API_PASSWORD", "P2_API_PASSWORD"),
        ))
    if provider == "P3":
        return all((
            _value(config, "MASSIVE_PROXY_USERNAME", "P3_PROXY_USERNAME"),
            _value(config, "MASSIVE_API_KEY", "P3_API_KEY"),
        ))
    if provider == "P4":
        return all((
            _value(config, "P4_PROXY_HOST", "P4_HOST"),
            _value(config, "P4_PROXY_PORT", "P4_PORT"),
            _value(config, "P4_PROXY_USERNAME", "P4_USERNAME"),
            _value(config, "P4_PROXY_PASSWORD", "P4_PASSWORD"),
        ))
    return False


def _generate(
    provider: str,
    country: str,
    region: str,
    city: str,
    count: int,
    config: dict,
) -> list[str]:
    provider = provider.upper()
    country = country.upper()
    result: list[str] = []
    if provider == "P1":
        account = _value(config, "NIMBLE_ACCOUNT_NAME", "P1_ACCOUNT_NAME")
        pipeline = _value(config, "NIMBLE_PIPELINE_NAME", "P1_PIPELINE_NAME")
        password = _value(config, "NIMBLE_PIPELINE_PASSWORD", "P1_PIPELINE_PASSWORD")
        if not all((account, pipeline, password)):
            raise ValueError("P1 credentials are unavailable")
        protocol = _protocol(config, provider)
        for _index in range(count):
            user = f"account-{account}-pipeline-{pipeline}-country-{country}"
            if region:
                user += f"-state-{region}"
            if city:
                user += f"-city-{re.sub(r'\s+', '_', city.lower())}"
            user += f"-session-{_session()}"
            result.append(_proxy_url(protocol, "ip.nimbleway.com", 7000, user, password))
    elif provider == "P2":
        username = _value(config, "INFATICA_API_USERNAME", "P2_API_USERNAME")
        password = _value(config, "INFATICA_API_PASSWORD", "P2_API_PASSWORD")
        if not all((username, password)):
            raise ValueError("P2 credentials are unavailable")
        protocol = _protocol(config, provider, "socks5")
        for index in range(count):
            port = 10000 + (index % 1000)
            user = f"{username}_c_{country}"
            if region:
                user += f"_sd_{region}"
            if city:
                user += "_city_" + re.sub(r"\s+", "-", city.strip())
            user += f"_s_{_session()}"
            result.append(_proxy_url(protocol, "pool.infatica.io", port, user, password))
    elif provider == "P3":
        username = _value(config, "MASSIVE_PROXY_USERNAME", "P3_PROXY_USERNAME")
        password = _value(config, "MASSIVE_API_KEY", "P3_API_KEY")
        if not all((username, password)):
            raise ValueError("P3 credentials are unavailable")
        protocol = _protocol(config, provider)
        for _index in range(count):
            user = f"{username}-country-{country}"
            if region:
                user += f"-subdivision-{region}"
            if city:
                # Massive expects the preferred English city spelling.  The
                # complete username is URL-encoded by _proxy_url(), so keep
                # spaces here rather than converting them to hyphens.
                user += f"-city-{city.strip()}"
            user += f"-session-{_session()}"
            result.append(
                _proxy_url(protocol, "network.joinmassive.com", 65534, user, password)
            )
    elif provider == "P4":
        host = _value(config, "P4_PROXY_HOST", "P4_HOST")
        raw_port = _value(config, "P4_PROXY_PORT", "P4_PORT")
        username = _value(config, "P4_PROXY_USERNAME", "P4_USERNAME")
        password = _value(config, "P4_PROXY_PASSWORD", "P4_PASSWORD")
        if not all((host, raw_port, username, password)):
            raise ValueError("P4 credentials are unavailable")
        port = _bounded_int(raw_port, default=0, minimum=1, maximum=65535)
        if not port:
            raise ValueError("P4 proxy port is invalid")
        protocol = _protocol(config, provider)
        sticky_minutes = _bounded_int(
            _value(config, "P4_STICKY_MINUTES"),
            default=60,
            minimum=1,
            maximum=120,
        )
        country_segment = _p4_location_segment(country)
        region_segment = _p4_location_segment(region)
        for _index in range(count):
            user = f"{username}-country-{country_segment}"
            if region_segment:
                user += f"-st-{region_segment}"
            user += f"-sst-{sticky_minutes}-ssid-{_session()}"
            result.append(_proxy_url(protocol, host, port, user, password))
    else:
        raise ValueError("Dynamic generation is not configured for this provider")
    return result


def ensure_pool_targets(
    *,
    target_count: int = DEFAULT_POOL_TARGET,
    replenish_below: int = DEFAULT_POOL_THRESHOLD,
    include_regions: bool = False,
) -> tuple[int, int]:
    """Create every global country target and supported P1/P2 region target."""
    target_count = max(1, int(target_count))
    replenish_below = max(0, min(int(replenish_below), target_count - 1))
    ensure_global_country_catalog()
    ensure_p1_region_catalog()
    countries = list(
        ProxyCountryFile.objects.filter(
            active=True,
            provider__active=True,
            provider__code__in=SUPPORTED_DYNAMIC_PROVIDERS,
        ).values_list("provider__code", "country_code")
    )
    regions = (
        list(
            ProxyRegionCatalog.objects.filter(
                active=True,
                provider__active=True,
                provider__code__in=("P1", "P2"),
            ).values_list("provider__code", "country_code", "region_code")
        )
        if include_regions
        else []
    )
    bundles = (
        ConfigBundle.objects.filter(active=True, clients__active=True)
        .distinct()
        .order_by("pk")
    )
    created = 0
    available_targets = 0
    for bundle in bundles:
        config = bundle.get_payload()
        configured = {
            code
            for code in SUPPORTED_DYNAMIC_PROVIDERS
            if provider_is_configured(code, config)
        }
        desired = {
            (provider_code.upper(), country_code.upper(), "", "")
            for provider_code, country_code in countries
            if provider_code.upper() in configured
        }
        desired.update(
            (
                provider_code.upper(),
                country_code.upper(),
                str(region_code),
                "",
            )
            for provider_code, country_code, region_code in regions
            if provider_code.upper() in configured
        )
        existing = set(
            ProxyPoolTarget.objects.filter(config_bundle=bundle).values_list(
                "provider_code", "country_code", "region", "city"
            )
        )
        missing = [
            ProxyPoolTarget(
                config_bundle=bundle,
                provider_code=provider_code,
                country_code=country_code,
                region=region,
                city=city,
                target_count=target_count,
                replenish_below=replenish_below,
                active=True,
            )
            for provider_code, country_code, region, city in desired - existing
        ]
        ProxyPoolTarget.objects.bulk_create(
            missing,
            batch_size=500,
            ignore_conflicts=True,
        )
        if missing:
            ProxyPoolTarget.objects.filter(
                config_bundle=bundle,
                provider_code__in=configured,
            ).filter(
                Q(target_count__lt=target_count)
                | Q(replenish_below__lt=replenish_below)
            ).update(
                target_count=target_count,
                replenish_below=replenish_below,
            )
        created += len(missing)
        available_targets += len(desired)
    return created, available_targets


def _mark_target_jobs_failed(target: ProxyPoolTarget, error: Exception) -> None:
    message = f"Proxy pool refill failed: {type(error).__name__}."[:1000]
    jobs = ProxyGenerationJob.objects.filter(
        client__config_bundle=target.config_bundle,
        provider_code=target.provider_code,
        country_code=target.country_code,
        region=target.region,
        city=target.city,
        status__in=("waiting_generation", "partial"),
    )
    jobs.filter(ready_count=0).update(status="failed", error=message)
    jobs.filter(ready_count__gt=0).update(status="partial", error=message)


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def refill_proxy_pool(self, target_id: int) -> int:
    """Fill one pool to its target and satisfy queued app jobs from that pool."""
    try:
        with transaction.atomic():
            target = (
                ProxyPoolTarget.objects.select_for_update()
                .select_related("config_bundle")
                .get(pk=target_id)
            )
            if not target.active:
                return 0
            available_before = target.entries.filter(state="available").count()
            needed = max(0, target.target_count - available_before)
            if needed:
                config = target.config_bundle.get_payload()
                if not provider_is_configured(target.provider_code, config):
                    raise ValueError(
                        f"{target.provider_code} credentials are unavailable"
                    )
                lines = _generate(
                    target.provider_code,
                    target.country_code,
                    target.region,
                    target.city,
                    needed,
                    config,
                )
                entries = []
                for line in lines:
                    entry = ProxyPoolEntry(
                        target=target,
                        proxy_fingerprint=proxy_fingerprint(line),
                    )
                    entry.set_proxy(line)
                    entries.append(entry)
                ProxyPoolEntry.objects.bulk_create(
                    entries,
                    batch_size=250,
                    ignore_conflicts=True,
                )
            available_after = target.entries.filter(state="available").count()
        fulfill_waiting_jobs(target)
        return max(0, available_after - available_before)
    except Exception as exc:
        try:
            target = ProxyPoolTarget.objects.select_related("config_bundle").get(
                pk=target_id
            )
            _mark_target_jobs_failed(target, exc)
        except ProxyPoolTarget.DoesNotExist:
            # A pool target can be deleted after a refill has already been
            # published to Redis.  That stale message has no remaining work
            # to perform, and must not be retried or logged as a worker error.
            return 0
        raise
    finally:
        ProxyPoolTarget.objects.filter(pk=target_id).update(
            refill_pending=False,
            refill_requested_at=None,
        )


def queue_refill_proxy_pool(target_id: int) -> bool:
    """Queue one refill and automatically recover abandoned pending flags."""
    now = timezone.now()
    stale_before = now - timedelta(
        seconds=max(60, int(getattr(settings, "PROXY_REFILL_STALE_SECONDS", 900)))
    )
    claimable = ProxyPoolTarget.objects.filter(
        pk=target_id,
        active=True,
    ).filter(
        Q(refill_pending=False)
        | Q(refill_requested_at__isnull=True)
        | Q(refill_requested_at__lte=stale_before)
    )
    claimed = claimable.update(
        refill_pending=True,
        refill_requested_at=now,
    )
    if not claimed:
        return False
    try:
        refill_proxy_pool.delay(target_id)
    except Exception as exc:
        ProxyPoolTarget.objects.filter(pk=target_id).update(
            refill_pending=False,
            refill_requested_at=None,
        )
        # The job and any already-reserved inventory are stored in MySQL. A
        # Redis/Celery outage must not turn an otherwise valid API request into
        # HTTP 500; the periodic maintainer can queue this target after Redis
        # recovers.
        logger.warning("Could not queue proxy refill for target %s: %s", target_id, exc)
        return False
    return True


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_proxy_inventory_alert(self, alert_id: int) -> None:
    """Deliver a durable proxy shortage record through the configured channel."""
    from .alerts import AlertConfigurationError, send_proxy_alert

    try:
        alert = ProxyInventoryAlert.objects.select_related("config_bundle").get(
            pk=alert_id
        )
    except ProxyInventoryAlert.DoesNotExist:
        return
    if not settings.PROXY_ALERT_ENABLED:
        ProxyInventoryAlert.objects.filter(pk=alert_id).update(
            status="disabled",
            error="Proxy inventory alerts are disabled in server configuration.",
        )
        return
    try:
        message_ids = send_proxy_alert(alert)
    except AlertConfigurationError as exc:
        ProxyInventoryAlert.objects.filter(pk=alert_id).update(
            status="config_error",
            error=str(exc)[:1000],
        )
        return
    except Exception as exc:
        ProxyInventoryAlert.objects.filter(pk=alert_id).update(
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:1000],
        )
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        return
    ProxyInventoryAlert.objects.filter(pk=alert_id).update(
        status="sent",
        provider_message_id=",".join(value for value in message_ids if value)[:80],
        error="",
        sent_at=timezone.now(),
    )


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def generate_proxy_job(self, job_id: int) -> None:
    """Compatibility task: route old queued messages through the shared pool."""
    job = ProxyGenerationJob.objects.select_related("client__config_bundle").get(pk=job_id)
    if job.status not in {"waiting_generation", "partial"}:
        return
    target = get_or_create_pool_target(
        client=job.client,
        provider_code=job.provider_code,
        country_code=job.country_code,
        region=job.region,
        city=job.city,
    )
    refill_proxy_pool.run(target.pk)


@shared_task
def maintain_proxy_pools(force: bool = False) -> int:
    """Refill demand-created pools without multiplying every bundle/region."""
    if force:
        sync_provider_geography()
    if not settings.AUTO_REFILL_PROXY_POOLS:
        return 0
    if settings.AUTO_CREATE_PROXY_POOL_TARGETS:
        # Even explicit eager provisioning is country-only. Region/state pools
        # remain on-demand because multiplying them across every bundle caused
        # the runaway inventory this guard is designed to prevent.
        ensure_pool_targets(include_regions=False)
    queued = 0
    targets = (
        ProxyPoolTarget.objects.filter(active=True)
        .select_related("config_bundle")
        .annotate(
            available_count=Count(
                "entries", filter=Q(entries__state="available")
            )
        )
    )
    configs: dict[int, dict] = {}
    for target in targets:
        config = configs.get(target.config_bundle_id)
        if config is None:
            config = target.config_bundle.get_payload()
            configs[target.config_bundle_id] = config
        if not provider_is_configured(target.provider_code, config):
            continue
        available = int(target.available_count)
        if available <= target.replenish_below:
            if queue_refill_proxy_pool(target.pk):
                queued += 1
    return queued


@shared_task
def sync_proxy_geography() -> dict[str, int]:
    """Refresh provider country/state metadata before the morning prefill."""
    return sync_provider_geography()
