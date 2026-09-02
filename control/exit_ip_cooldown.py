from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from .models import (
    ClientAccess,
    ProxyExitIPCooldown,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyReservation,
)


@dataclass(frozen=True)
class ExitIPClaimResult:
    cooldown: ProxyExitIPCooldown
    claimed: bool
    idempotent: bool = False


@dataclass(frozen=True)
class ExitIPCheckResult:
    cooldown: ProxyExitIPCooldown | None
    duplicate: bool


def normalize_exit_ip(value: object) -> str:
    """Return the canonical spelling used as the global database key."""
    address = ipaddress.ip_address(str(value or "").strip())
    # Treat an IPv4-mapped IPv6 report as the same exit as its IPv4 spelling;
    # otherwise clients using different IP-discovery services could bypass the
    # global key with ``::ffff:198.51.100.1``.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def cooldown_seconds() -> int:
    return max(1, int(settings.PROXY_EXIT_IP_COOLDOWN_SECONDS))


def _record_pool_test(
    reservation: ProxyReservation | None,
    *,
    exit_ip: str,
    fraud_score: int | None,
    tested_at,
) -> None:
    if reservation is None or not reservation.pool_entry_id:
        return
    ProxyPoolEntry.objects.filter(pk=reservation.pool_entry_id).update(
        exit_ip=exit_ip,
        fraud_score=fraud_score,
        tested_at=tested_at,
    )


def check_exit_ip(
    *,
    exit_ip: object,
    reservation: ProxyReservation | None = None,
    now=None,
) -> ExitIPCheckResult:
    """Non-mutating early check; the later atomic claim remains authoritative."""
    normalized_ip = normalize_exit_ip(exit_ip)
    checked_at = now or timezone.now()
    cooldown = ProxyExitIPCooldown.objects.filter(exit_ip=normalized_ip).first()
    duplicate = bool(
        cooldown is not None
        and cooldown.available_after > checked_at
        and (
            reservation is None
            or cooldown.reservation_id != reservation.pk
        )
    )
    return ExitIPCheckResult(cooldown=cooldown, duplicate=duplicate)


def claim_exit_ip(
    *,
    client: ClientAccess,
    provider_code: str,
    exit_ip: object,
    job: ProxyGenerationJob | None = None,
    reservation: ProxyReservation | None = None,
    fraud_score: int | None = None,
    now=None,
) -> ExitIPClaimResult:
    """Atomically claim one exit IP across all providers and clients.

    The unique IP constraint closes the race for a previously unseen address;
    ``select_for_update`` serializes expiry decisions for existing addresses.
    Replaying the same non-null reservation is idempotent so a lost response
    does not make the desktop discard an otherwise successful claim.
    """
    normalized_ip = normalize_exit_ip(exit_ip)
    if fraud_score is not None:
        fraud_score = int(fraud_score)
        if not 0 <= fraud_score <= 100:
            raise ValueError("Invalid fraud score")
    claimed_at = now or timezone.now()
    available_after = claimed_at + timedelta(seconds=cooldown_seconds())

    with transaction.atomic():
        cooldown = (
            ProxyExitIPCooldown.objects.select_for_update()
            .filter(exit_ip=normalized_ip)
            .first()
        )
        created = False
        if cooldown is None:
            # Concurrent first claims can both see an empty lookup. The unique
            # key chooses one winner; the other transaction then locks it.
            try:
                with transaction.atomic():
                    cooldown = ProxyExitIPCooldown.objects.create(
                        exit_ip=normalized_ip,
                        client=client,
                        job=job,
                        reservation=reservation,
                        provider_code=provider_code,
                        fraud_score=fraud_score,
                        claimed_at=claimed_at,
                        available_after=available_after,
                    )
                created = True
            except IntegrityError:
                cooldown = ProxyExitIPCooldown.objects.select_for_update().get(
                    exit_ip=normalized_ip
                )

        if created:
            _record_pool_test(
                reservation,
                exit_ip=normalized_ip,
                fraud_score=fraud_score,
                tested_at=claimed_at,
            )
            return ExitIPClaimResult(cooldown=cooldown, claimed=True)

        if (
            reservation is not None
            and cooldown.reservation_id == reservation.pk
            and cooldown.available_after > claimed_at
        ):
            # An HTTP retry may carry richer quality metadata. Keep the
            # original 25-hour window unchanged while enriching its audit.
            if fraud_score is not None and cooldown.fraud_score != fraud_score:
                cooldown.fraud_score = fraud_score
                cooldown.save(update_fields=("fraud_score", "updated_at"))
            _record_pool_test(
                reservation,
                exit_ip=normalized_ip,
                fraud_score=fraud_score,
                tested_at=claimed_at,
            )
            return ExitIPClaimResult(
                cooldown=cooldown,
                claimed=True,
                idempotent=True,
            )

        if cooldown.available_after > claimed_at:
            ProxyExitIPCooldown.objects.filter(pk=cooldown.pk).update(
                duplicate_attempts=F("duplicate_attempts") + 1,
                last_duplicate_at=claimed_at,
                updated_at=claimed_at,
            )
            cooldown.refresh_from_db(
                fields=("duplicate_attempts", "last_duplicate_at", "updated_at")
            )
            _record_pool_test(
                reservation,
                exit_ip=normalized_ip,
                fraud_score=fraud_score,
                tested_at=claimed_at,
            )
            return ExitIPClaimResult(cooldown=cooldown, claimed=False)

        cooldown.client = client
        cooldown.job = job
        cooldown.reservation = reservation
        cooldown.provider_code = provider_code
        cooldown.fraud_score = fraud_score
        cooldown.claimed_at = claimed_at
        cooldown.available_after = available_after
        cooldown.save(
            update_fields=(
                "client",
                "job",
                "reservation",
                "provider_code",
                "fraud_score",
                "claimed_at",
                "available_after",
                "updated_at",
            )
        )
        _record_pool_test(
            reservation,
            exit_ip=normalized_ip,
            fraud_score=fraud_score,
            tested_at=claimed_at,
        )
        return ExitIPClaimResult(cooldown=cooldown, claimed=True)
