from __future__ import annotations

import hashlib
import re
import urllib.parse
from collections.abc import Iterable

from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from .models import (
    ClientAccess,
    ProxyCountryFile,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyReservation,
)


def proxy_fingerprint(value: str) -> str:
    """Stable, secret-free identifier for a proxy line."""
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _repair_legacy_p3_city_proxy(value: str, city: str) -> str:
    """Upgrade a pre-fix Massive city username without exposing credentials.

    Older pool rows used hyphens in the ``city`` username segment.  Massive
    requires the preferred city spelling and percent-encoded spaces instead.
    Pool values are encrypted, therefore repair an old row only when it is
    about to be issued rather than performing a risky bulk rewrite.
    """
    requested_city = str(city or "").strip()
    if not requested_city:
        return value
    parsed = urllib.parse.urlsplit(value)
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    repaired_username, substitutions = re.subn(
        r"(?<=-city-).*?(?=-session-)", requested_city, username, count=1
    )
    if not substitutions or repaired_username == username:
        return value
    host = parsed.hostname or ""
    if not host:
        return value
    port = f":{parsed.port}" if parsed.port else ""
    auth = (
        f"{urllib.parse.quote(repaired_username, safe='')}:"
        f"{urllib.parse.quote(password, safe='')}@"
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, f"{auth}{host}{port}", parsed.path, parsed.query, parsed.fragment)
    )


def reservation_target(job: ProxyGenerationJob) -> int:
    """Candidates may exceed profiles when local quality testing is enabled."""
    return max(
        int(job.requested_count or 1),
        int(getattr(job, "candidate_count", 1) or 1),
    )



def _locked(queryset):
    """Avoid serialising independent client reservations on MySQL 8+."""
    if connection.features.has_select_for_update_skip_locked:
        return queryset.select_for_update(skip_locked=True)
    return queryset.select_for_update()


def usable_lines(content: str) -> Iterable[str]:
    for raw in content.splitlines():
        value = raw.strip()
        if value and not value.startswith("#"):
            yield value


@transaction.atomic
def reserve_static_proxies(
    *,
    client: ClientAccess,
    job: ProxyGenerationJob,
    provider_code: str,
    country_code: str,
    region: str = "",
    city: str = "",
) -> list[ProxyReservation]:
    """Reserve never-before-issued lines from a country's encrypted catalog."""
    source = (
        _locked(ProxyCountryFile.objects.select_related("provider"))
        .filter(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            active=True,
        )
        .first()
    )
    if source is None:
        return []
    remaining = max(0, reservation_target(job) - job.reservations.count())
    reservations: list[ProxyReservation] = []
    for value in usable_lines(source.get_content()):
        if len(reservations) >= remaining:
            break
        try:
            with transaction.atomic():
                reservation = ProxyReservation(
                    client=client,
                    job=job,
                    provider_code=provider_code,
                    country_code=country_code,
                    region=region,
                    city=city,
                    proxy_fingerprint=proxy_fingerprint(value),
                )
                reservation.set_proxy(value)
                reservation.save(force_insert=True)
        except IntegrityError:
            continue
        reservations.append(reservation)
    return reservations


@transaction.atomic
def reserve_pool_proxies(
    *,
    client: ClientAccess,
    job: ProxyGenerationJob,
    provider_code: str,
    country_code: str,
    region: str = "",
    city: str = "",
) -> list[ProxyReservation]:
    """Atomically issue unused, pre-generated pool entries exactly once."""
    remaining = max(0, reservation_target(job) - job.reservations.count())
    if not remaining:
        return []
    entries = (
        _locked(ProxyPoolEntry.objects)
        .filter(
            target__config_bundle=client.config_bundle,
            target__provider_code=provider_code,
            target__country_code=country_code,
            target__region=region,
            target__city=city,
            target__active=True,
            state="available",
        )
        .order_by("created_at", "pk")[:remaining]
    )
    now = timezone.now()
    issued: list[ProxyReservation] = []
    for entry in entries:
        value = entry.get_proxy()
        if provider_code == "P3" and city:
            repaired_value = _repair_legacy_p3_city_proxy(value, city)
            if repaired_value != value:
                entry.set_proxy(repaired_value)
                entry.proxy_fingerprint = proxy_fingerprint(repaired_value)
                value = repaired_value
        entry.state = "reserved"
        entry.reserved_client = client
        entry.reserved_at = now
        entry.save(
            update_fields=(
                "proxy_ciphertext",
                "proxy_fingerprint",
                "state",
                "reserved_client",
                "reserved_at",
            )
        )
        reservation = ProxyReservation(
            client=client,
            job=job,
            pool_entry=entry,
            provider_code=provider_code,
            country_code=country_code,
            region=region,
            city=city,
            proxy_fingerprint=entry.proxy_fingerprint,
        )
        reservation.set_proxy(value)
        reservation.save(force_insert=True)
        issued.append(reservation)
    return issued


def fulfill_waiting_jobs(target: ProxyPoolTarget) -> int:
    """Attach newly generated pool entries to waiting jobs, oldest first."""
    completed = 0
    jobs = (
        ProxyGenerationJob.objects.select_related("client")
        .filter(
            client__config_bundle=target.config_bundle,
            provider_code=target.provider_code,
            country_code=target.country_code,
            region=target.region,
            city=target.city,
            status__in=("waiting_generation", "partial"),
        )
        .order_by("created_at", "pk")
    )
    for job in jobs:
        reserve_pool_proxies(
            client=job.client,
            job=job,
            provider_code=job.provider_code,
            country_code=job.country_code,
            region=job.region,
            city=job.city,
        )
        ready_count = job.reservations.count()
        if ready_count >= reservation_target(job):
            status = "ready"
            completed += 1
        elif ready_count:
            status = "partial"
        else:
            status = "waiting_generation"
        ProxyGenerationJob.objects.filter(pk=job.pk).update(
            ready_count=ready_count,
            status=status,
            error="",
            updated_at=timezone.now(),
        )
        if target.entries.filter(state="available").count() == 0:
            break
    return completed


def get_or_create_pool_target(
    *,
    client: ClientAccess,
    provider_code: str,
    country_code: str,
    region: str = "",
    city: str = "",
) -> ProxyPoolTarget:
    target, _created = ProxyPoolTarget.objects.get_or_create(
        config_bundle=client.config_bundle,
        provider_code=provider_code,
        country_code=country_code,
        region=region,
        city=city,
        defaults={"target_count": 1000, "replenish_below": 200, "active": True},
    )
    return target
