from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.core.exceptions import ValidationError


logger = logging.getLogger("control")

# This public key is also pinned in the updater-capable desktop build. The
# corresponding private key must remain outside the Django host.
DESKTOP_RELEASE_PUBLIC_KEY_B64 = (
    "uwSLdhZ0tEStqleAnaPLvVDijXXpoDUdfbFlXosz3I8="
)
DESKTOP_RELEASE_PRODUCT = "quest-automation"
DESKTOP_RELEASE_SCHEMA_VERSION = 1
DESKTOP_COMPONENT_SCHEMA_VERSION = 1


def artifact_sha256_and_size(file_value: Any) -> tuple[str, int]:
    """Hash an uploaded or stored file without retaining its bytes in memory."""
    if not file_value:
        return "", 0
    source = getattr(file_value, "file", file_value)
    original_position: int | None = None
    try:
        original_position = source.tell()
    except (AttributeError, OSError):
        pass
    try:
        source.seek(0)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        return digest.hexdigest(), size
    finally:
        try:
            source.seek(0 if original_position is None else original_position)
        except (AttributeError, OSError):
            pass


def canonical_release_payload(release: Any) -> bytes:
    """Return the exact bytes signed offline and verified by the desktop."""
    payload = {
        "build_number": int(release.build_number),
        "channel": str(release.channel),
        "product": DESKTOP_RELEASE_PRODUCT,
        "schema_version": DESKTOP_RELEASE_SCHEMA_VERSION,
        "sha256": str(release.artifact_sha256),
        "size": int(release.artifact_size),
        "version": str(release.version),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_component_payload(release: Any) -> bytes:
    """Return the stable payload shared by Django and the OPTIX component loader."""
    payload = {
        "activation": str(release.activation),
        "build_number": int(release.build_number),
        "channel": str(release.channel),
        "component": str(release.component),
        "metadata": release.metadata or {},
        "product": DESKTOP_RELEASE_PRODUCT,
        "schema_version": DESKTOP_COMPONENT_SCHEMA_VERSION,
        "sha256": str(release.artifact_sha256),
        "size": int(release.artifact_size),
        "slot": str(release.slot),
        "version": str(release.version),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def verify_release_signature(release: Any) -> None:
    """Raise ValidationError unless the detached Ed25519 signature is valid."""
    signature_text = str(release.signature_b64 or "").strip()
    if not signature_text:
        raise ValidationError({"signature_b64": "A release signature is required."})
    try:
        public_key_raw = base64.b64decode(
            DESKTOP_RELEASE_PUBLIC_KEY_B64,
            validate=True,
        )
        signature = base64.b64decode(signature_text, validate=True)
        if len(public_key_raw) != 32 or len(signature) != 64:
            raise ValueError("Invalid Ed25519 material length")
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            signature,
            canonical_release_payload(release),
        )
    except (binascii.Error, InvalidSignature, TypeError, ValueError) as exc:
        raise ValidationError(
            {"signature_b64": "The Ed25519 release signature is invalid."}
        ) from exc


def verify_component_signature(release: Any) -> None:
    """Raise ValidationError unless a component has a valid detached signature."""
    signature_text = str(release.signature_b64 or "").strip()
    if not signature_text:
        raise ValidationError({"signature_b64": "A component signature is required."})
    try:
        public_key_raw = base64.b64decode(DESKTOP_RELEASE_PUBLIC_KEY_B64, validate=True)
        signature = base64.b64decode(signature_text, validate=True)
        if len(public_key_raw) != 32 or len(signature) != 64:
            raise ValueError("Invalid Ed25519 material length")
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            signature,
            canonical_component_payload(release),
        )
    except (binascii.Error, InvalidSignature, TypeError, ValueError) as exc:
        raise ValidationError(
            {"signature_b64": "The Ed25519 component signature is invalid."}
        ) from exc


def verify_artifact_integrity(release: Any) -> None:
    """Re-hash the stored artifact before an administrator publishes it."""
    if not release.artifact:
        raise ValidationError({"artifact": "A release artifact is required."})
    try:
        release.artifact.open("rb")
        digest, size = artifact_sha256_and_size(release.artifact)
    except OSError as exc:
        raise ValidationError({"artifact": "The release artifact is unavailable."}) from exc
    finally:
        try:
            release.artifact.close()
        except (AttributeError, OSError):
            pass
    if digest != release.artifact_sha256 or size != release.artifact_size:
        raise ValidationError(
            {"artifact": "The stored release artifact failed its integrity check."}
        )


def verify_component_artifact_integrity(release: Any) -> None:
    """Re-hash a stored component package immediately before publication."""
    if not release.artifact:
        raise ValidationError({"artifact": "A component artifact is required."})
    try:
        release.artifact.open("rb")
        digest, size = artifact_sha256_and_size(release.artifact)
    except OSError as exc:
        raise ValidationError({"artifact": "The component artifact is unavailable."}) from exc
    finally:
        try:
            release.artifact.close()
        except (AttributeError, OSError):
            pass
    if digest != release.artifact_sha256 or size != release.artifact_size:
        raise ValidationError(
            {"artifact": "The stored component artifact failed its integrity check."}
        )


def release_applies_to_client(release: Any, client: Any) -> bool:
    offices = {
        str(value).strip().casefold()
        for value in (release.target_offices or [])
        if str(value).strip()
    }
    device_ids = {
        str(value).strip()
        for value in (release.target_device_ids or [])
        if str(value).strip()
    }
    if offices and str(client.office_name or "").strip().casefold() not in offices:
        return False
    if device_ids and str(client.device_id or "").strip() not in device_ids:
        return False
    return True


def select_component_updates(*, client: Any) -> list[Any]:
    """Return the newest valid applicable release for every component name."""
    from .models import DesktopComponentRelease

    selected: dict[tuple[str, str], Any] = {}
    candidates = DesktopComponentRelease.objects.filter(
        channel=client.release_channel,
        status=DesktopComponentRelease.STATUS_PUBLISHED,
    ).exclude(artifact="").order_by("component", "slot", "-build_number", "-pk")
    for release in candidates:
        key = (release.component, release.slot)
        if key in selected or not release_applies_to_client(release, client):
            continue
        try:
            if not release.artifact.storage.exists(release.artifact.name):
                continue
            verify_component_signature(release)
        except (OSError, ValidationError):
            logger.exception("Ignoring invalid component release %s", release.pk)
            continue
        selected[key] = release
    return [selected[key] for key in sorted(selected)]


def component_update_manifest(release: Any) -> dict[str, Any]:
    payload = json.loads(canonical_component_payload(release).decode("utf-8"))
    payload.update(
        {
            "id": int(release.pk),
            "download_path": f"/api/v1/desktop-components/{int(release.pk)}/",
            "filename": str(release.original_filename),
            "signature": str(release.signature_b64).strip(),
        }
    )
    return payload


def select_desktop_update(*, client: Any, app_build: int) -> Any | None:
    """Select the newest valid published release assigned to this device."""
    from .models import DesktopRelease

    candidates = DesktopRelease.objects.filter(
        channel=client.release_channel,
        status=DesktopRelease.STATUS_PUBLISHED,
        build_number__gt=max(0, int(app_build)),
    ).exclude(artifact="").order_by("-build_number", "-pk")
    for release in candidates:
        if not release_applies_to_client(release, client):
            continue
        try:
            if not release.artifact.storage.exists(release.artifact.name):
                logger.error(
                    "Published desktop release %s has no stored artifact",
                    release.pk,
                )
                continue
        except OSError:
            logger.exception(
                "Could not check the artifact for desktop release %s",
                release.pk,
            )
            continue
        try:
            verify_release_signature(release)
        except ValidationError:
            logger.error(
                "Published desktop release %s has an invalid signature",
                release.pk,
            )
            continue
        return release
    return None


def desktop_update_manifest(release: Any) -> dict[str, Any]:
    payload = json.loads(canonical_release_payload(release).decode("utf-8"))
    payload.update(
        {
            "id": int(release.pk),
            "mode": release.mode,
            "download_path": f"/api/v1/desktop-releases/{int(release.pk)}/",
            "signature": str(release.signature_b64).strip(),
        }
    )
    return payload
