from __future__ import annotations

import hashlib

from django.core.cache import cache


ACCESS_AUDIT_VERSION_KEY = "panel:access-audit:version"
ACCESS_AUDIT_MIN_TTL = (11 * 60 + 5) * 60
ACCESS_AUDIT_MAX_TTL = (12 * 60 + 10) * 60


def safe_cache_get(key: str, default=None):
    """Read an optional panel cache without making Redis a hard dependency."""
    try:
        return cache.get(key, default)
    except Exception:
        return default


def safe_cache_set(key: str, value, timeout=None) -> bool:
    """Best-effort cache write; database-backed panel data remains canonical."""
    try:
        cache.set(key, value, timeout=timeout)
        return True
    except Exception:
        return False


def access_audit_cache_version() -> int:
    """Return the shared audit snapshot version used by all web workers."""
    try:
        cache.add(ACCESS_AUDIT_VERSION_KEY, 1, timeout=None)
        return int(cache.get(ACCESS_AUDIT_VERSION_KEY) or 1)
    except Exception:
        return 1


def bump_access_audit_cache_version() -> int:
    """Invalidate audit page caches without scanning/deleting Redis keys."""
    try:
        if cache.add(ACCESS_AUDIT_VERSION_KEY, 2, timeout=None):
            return 2
        return int(cache.incr(ACCESS_AUDIT_VERSION_KEY))
    except Exception:
        return 2


def access_audit_cache_ttl(cache_key: str) -> int:
    """Spread old cache expiry between 11h05m and 12h10m."""
    spread = ACCESS_AUDIT_MAX_TTL - ACCESS_AUDIT_MIN_TTL
    digest = hashlib.sha256(cache_key.encode("utf-8")).digest()
    return ACCESS_AUDIT_MIN_TTL + int.from_bytes(digest[:4], "big") % (spread + 1)
