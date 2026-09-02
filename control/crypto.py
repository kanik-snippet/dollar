from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _fernet() -> Fernet:
    secret = settings.CONFIG_ENCRYPTION_SECRET
    if not secret:
        raise ImproperlyConfigured("CONFIG_ENCRYPTION_SECRET is required.")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_text(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_text(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Encrypted data cannot be decrypted. Check CONFIG_ENCRYPTION_SECRET."
        ) from exc


def encrypt_json(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return encrypt_text(payload)


def decrypt_json(value: str) -> dict[str, Any]:
    payload = json.loads(decrypt_text(value))
    if not isinstance(payload, dict):
        raise ValueError("The decrypted configuration must be a JSON object.")
    return payload
