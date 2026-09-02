from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator, MinValueValidator, RegexValidator
from django.db import models, transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .crypto import decrypt_json, decrypt_text, encrypt_json, encrypt_text
from .storage import private_desktop_release_storage


catalog_id_validator = RegexValidator(
    regex=r"^[A-Za-z0-9_-]{1,32}$",
    message="Use only letters, numbers, underscores, and hyphens.",
)

desktop_version_validator = RegexValidator(
    regex=r"\A[0-9]+(?:\.[0-9]+){2,3}\Z",
    message="Use a numeric dotted version such as 1.7.35.",
)

component_version_validator = RegexValidator(
    regex=r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z",
    message="Use 1-64 letters, numbers, dots, underscores, or hyphens.",
)

logger = logging.getLogger("control")


def desktop_release_artifact_path(instance, filename: str) -> str:
    """Store release binaries outside any predictable/public media path."""
    return f"desktop-releases/{uuid.uuid4().hex}.exe"


def desktop_component_artifact_path(instance, filename: str) -> str:
    """Keep signed component packages private while retaining their safe suffix."""
    suffix = str(filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    suffix = suffix.rpartition(".")[2].casefold()
    suffix = suffix if suffix in {"zip", "json"} else "bin"
    return f"desktop-components/{uuid.uuid4().hex}.{suffix}"


class ConfigBundle(models.Model):
    name = models.CharField(max_length=120, unique=True)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    browser_group_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Numeric browser group ID assigned to every device using this bundle.",
    )
    browser_group_name = models.CharField(
        max_length=160,
        default="Testing",
        help_text="Browser group name used for display and as a fallback when no ID is set.",
    )
    payload_ciphertext = models.TextField(blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} (v{self.version})"

    def set_payload(self, payload: dict[str, Any]) -> None:
        self.payload_ciphertext = encrypt_json(payload)

    def get_payload(self) -> dict[str, Any]:
        return decrypt_json(self.payload_ciphertext) if self.payload_ciphertext else {}


class ClientAccess(models.Model):
    RELEASE_CHANNEL_PUBLIC = "public"
    RELEASE_CHANNEL_TESTING = "testing"
    RELEASE_CHANNEL_CHOICES = (
        (RELEASE_CHANNEL_PUBLIC, "Public"),
        (RELEASE_CHANNEL_TESTING, "Testing"),
    )
    ACTIVATION_INHERIT = "inherit"
    ACTIVATION_REQUIRE = "require"
    ACTIVATION_BYPASS = "bypass"
    ACTIVATION_MODE_CHOICES = (
        (ACTIVATION_INHERIT, "Inherit global OPTIX activation setting"),
        (ACTIVATION_REQUIRE, "Require OPTIX activation for this PC"),
        (ACTIVATION_BYPASS, "Legacy bypass — do not require OPTIX activation"),
    )

    name = models.CharField(max_length=120)
    ipv4 = models.GenericIPAddressField(protocol="IPv4")
    device_id = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Stable desktop identifier; leave blank for IP-only access.",
    )
    active = models.BooleanField(default=True)
    office_name = models.CharField(max_length=64)
    system_number = models.CharField(max_length=32)
    profile_name = models.CharField(
        max_length=160,
        blank=True,
        default="",
        help_text="Fixed browser profile name for this device. Defaults to the access-record name.",
    )
    config_bundle = models.ForeignKey(
        ConfigBundle,
        on_delete=models.PROTECT,
        related_name="clients",
    )
    release_channel = models.CharField(
        max_length=16,
        choices=RELEASE_CHANNEL_CHOICES,
        default=RELEASE_CHANNEL_PUBLIC,
        help_text="Desktop release channel assigned by an administrator.",
    )
    activation_mode = models.CharField(
        max_length=16,
        choices=ACTIVATION_MODE_CHOICES,
        default=ACTIVATION_INHERIT,
        help_text="Override the global OPTIX activation requirement for this individual PC.",
    )
    notes = models.TextField(blank=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("office_name", "system_number", "name")
        verbose_name_plural = "Client access entries"
        constraints = [
            models.UniqueConstraint(
                fields=("ipv4", "device_id"),
                name="unique_ipv4_device_access",
            )
        ]

    def __str__(self) -> str:
        return f"{self.office_name} / sys_{self.system_number} / {self.ipv4}"


class ClientAccessIP(models.Model):
    """Additional public IPv4 allowed for an existing client/device."""

    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.CASCADE,
        related_name="allowed_ips",
    )
    ipv4 = models.GenericIPAddressField(protocol="IPv4")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("ipv4",)
        verbose_name = "Additional client IPv4"
        verbose_name_plural = "Additional client IPv4s"
        constraints = [
            models.UniqueConstraint(
                fields=("client", "ipv4"),
                name="unique_client_allowed_ipv4",
            )
        ]

    def clean(self):
        if self.client_id and self.client and str(self.ipv4) == str(self.client.ipv4):
            raise ValidationError({"ipv4": "This is already the client's primary IPv4."})

    def __str__(self) -> str:
        return f"{self.client} / {self.ipv4}"


class YSBridgeAgent(models.Model):
    """A trusted Windows agent that can reach the local YSBrowser API."""

    name = models.CharField(max_length=120, unique=True)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    token_hint = models.CharField(max_length=16, blank=True, editable=False)
    active = models.BooleanField(default=True)
    version = models.CharField(max_length=40, blank=True, default="")
    last_ip = models.GenericIPAddressField(blank=True, null=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    @staticmethod
    def hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def set_token(self, raw_token: str) -> None:
        self.token_hash = self.hash_token(raw_token)
        self.token_hint = raw_token[:12]

    def check_token(self, raw_token: str) -> bool:
        return hmac.compare_digest(self.token_hash, self.hash_token(raw_token))

    def __str__(self) -> str:
        return self.name


class YSBridgeCommand(models.Model):
    ACTION_DELETE_ENVIRONMENTS = "delete_environments"
    ACTION_WHITELIST_ADD = "whitelist_add"
    ACTION_WHITELIST_REMOVE = "whitelist_remove"
    ACTION_CHOICES = (
        (ACTION_DELETE_ENVIRONMENTS, "Delete YSBrowser environments"),
        (ACTION_WHITELIST_ADD, "Add YSBrowser whitelist IP"),
        (ACTION_WHITELIST_REMOVE, "Remove YSBrowser whitelist IP"),
    )
    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_SUCCEEDED = "succeeded"
    STATUS_FAILED = "failed"
    STATUS_CANCELLED = "cancelled"
    STATUS_CHOICES = (
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_FAILED, "Failed"),
        (STATUS_CANCELLED, "Cancelled"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(
        YSBridgeAgent,
        on_delete=models.PROTECT,
        related_name="commands",
    )
    action = models.CharField(max_length=40, choices=ACTION_CHOICES)
    office_name = models.CharField(max_length=160, blank=True, default="")
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ys_bridge_commands",
    )
    result = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    requested_at = models.DateTimeField(auto_now_add=True)
    claimed_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-requested_at",)
        indexes = [
            models.Index(
                fields=("agent", "status", "requested_at"),
                name="ysbridge_claim_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.action} / {self.office_name or 'global'} / {self.status}"

class Provider(models.Model):
    code = models.CharField(max_length=32, unique=True, validators=[catalog_id_validator])
    display_name = models.CharField(max_length=64)
    display_order = models.PositiveIntegerField(default=0)
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ("display_order", "code")

    def __str__(self) -> str:
        return self.display_name


class ProxyCountryFile(models.Model):
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="country_files",
    )
    country_code = models.CharField(max_length=32, validators=[catalog_id_validator])
    country_name = models.CharField(max_length=80)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    content_ciphertext = models.TextField(blank=True, editable=False)
    content_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("provider__display_order", "country_name")
        constraints = [
            models.UniqueConstraint(
                fields=("provider", "country_code"),
                name="unique_provider_country_file",
            )
        ]

    def __str__(self) -> str:
        return f"{self.provider.code} / {self.country_name}"

    def set_content(self, content: str) -> None:
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        self.content_ciphertext = encrypt_text(normalized)
        self.content_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def get_content(self) -> str:
        return decrypt_text(self.content_ciphertext) if self.content_ciphertext else ""


class ProxyRegionCatalog(models.Model):
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="region_catalog",
    )
    country_code = models.CharField(max_length=32, validators=[catalog_id_validator])
    region_code = models.CharField(max_length=120)
    region_name = models.CharField(max_length=160)
    source = models.CharField(max_length=40, blank=True, default="")
    active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("provider__display_order", "country_code", "region_name")
        constraints = [
            models.UniqueConstraint(
                fields=("provider", "country_code", "region_code"),
                name="unique_provider_country_region",
            )
        ]

    def __str__(self) -> str:
        return (
            f"{self.provider.code} / {self.country_code} / "
            f"{self.region_name}"
        )


class ProxyCityCatalog(models.Model):
    """Provider geography shared by bundles using the same provider account."""

    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="city_catalog",
    )
    account_key = models.CharField(max_length=64)
    country_code = models.CharField(max_length=32, validators=[catalog_id_validator])
    region_code = models.CharField(max_length=120, blank=True)
    city_name = models.CharField(max_length=120)
    source = models.CharField(max_length=40, blank=True, default="")
    active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = (
            "provider__display_order",
            "account_key",
            "country_code",
            "region_code",
            "city_name",
        )
        constraints = [
            models.UniqueConstraint(
                fields=(
                    "provider",
                    "account_key",
                    "country_code",
                    "region_code",
                    "city_name",
                ),
                name="unique_p2_account_country_region_city",
            )
        ]
        indexes = [
            models.Index(
                fields=(
                    "provider",
                    "account_key",
                    "country_code",
                    "region_code",
                    "active",
                ),
                name="proxycity_account_scope_idx",
            )
        ]

    def __str__(self) -> str:
        location = f"{self.country_code} / "
        if self.region_code:
            location += f"{self.region_code} / "
        return (
            f"{self.provider.code} / {self.account_key[:8]} / "
            f"{location}{self.city_name}"
        )


class ExtensionPackage(models.Model):
    name = models.CharField(max_length=120, unique=True)
    filename = models.CharField(max_length=180)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    is_top = models.BooleanField(default=False)
    status = models.BooleanField(default=True)
    package_ciphertext = models.TextField(blank=True, editable=False)
    package_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} (v{self.version})"

    def set_package(self, raw: bytes) -> None:
        self.package_ciphertext = encrypt_text(base64.b64encode(raw).decode("ascii"))
        self.package_sha256 = hashlib.sha256(raw).hexdigest()

    def get_package(self) -> bytes:
        if not self.package_ciphertext:
            return b""
        return base64.b64decode(decrypt_text(self.package_ciphertext))


class DesktopRelease(models.Model):
    CHANNEL_PUBLIC = "public"
    CHANNEL_TESTING = "testing"
    CHANNEL_CHOICES = (
        (CHANNEL_PUBLIC, "Public"),
        (CHANNEL_TESTING, "Testing"),
    )

    MODE_OPTIONAL = "optional"
    MODE_SILENT = "silent"
    MODE_MANDATORY = "mandatory"
    MODE_CHOICES = (
        (MODE_OPTIONAL, "Optional"),
        (MODE_SILENT, "Silent automatic install"),
        (MODE_MANDATORY, "Mandatory automatic install"),
    )

    STATUS_DRAFT = "draft"
    STATUS_PUBLISHED = "published"
    STATUS_REVOKED = "revoked"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_PUBLISHED, "Published"),
        (STATUS_REVOKED, "Revoked"),
    )

    channel = models.CharField(
        max_length=16,
        choices=CHANNEL_CHOICES,
        default=CHANNEL_PUBLIC,
    )
    version = models.CharField(
        max_length=40,
        validators=[desktop_version_validator],
        help_text="Numeric dotted version, for example 1.7.35.",
    )
    build_number = models.PositiveBigIntegerField(
        help_text="Monotonically increasing build number within this channel.",
        validators=[MinValueValidator(1)],
    )
    mode = models.CharField(
        max_length=16,
        choices=MODE_CHOICES,
        default=MODE_OPTIONAL,
    )
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_DRAFT,
        editable=False,
    )
    target_offices = models.JSONField(
        default=list,
        blank=True,
        help_text="Office names allowed to receive this release; [] targets all offices.",
    )
    target_device_ids = models.JSONField(
        default=list,
        blank=True,
        help_text="Device IDs allowed to receive this release; [] targets all devices.",
    )
    artifact = models.FileField(
        storage=private_desktop_release_storage,
        upload_to=desktop_release_artifact_path,
        validators=[FileExtensionValidator(allowed_extensions=("exe",))],
    )
    original_filename = models.CharField(
        max_length=255,
        blank=True,
        editable=False,
    )
    artifact_sha256 = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
    )
    artifact_size = models.PositiveBigIntegerField(default=0, editable=False)
    signature_b64 = models.TextField(
        blank=True,
        default="",
        help_text="Detached Ed25519 signature of the canonical manifest payload.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="desktop_releases",
    )
    published_at = models.DateTimeField(blank=True, null=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-build_number", "-pk")
        constraints = [
            models.UniqueConstraint(
                fields=("channel", "build_number"),
                name="unique_desktop_release_build",
            ),
        ]
        indexes = [
            models.Index(
                fields=("channel", "status", "-build_number"),
                name="release_lookup_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.version} (build {self.build_number}, {self.channel})"

    @staticmethod
    def _clean_target_list(value: Any, field_name: str) -> list[str]:
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            raise ValidationError({field_name: "Enter a JSON list of strings."})
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError({field_name: "Every list item must be a string."})
            item = item.strip()
            if not item or len(item) > 160:
                raise ValidationError(
                    {field_name: "List items must be non-empty and at most 160 characters."}
                )
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    def clean(self) -> None:
        super().clean()
        self.target_offices = self._clean_target_list(
            self.target_offices,
            "target_offices",
        )
        self.target_device_ids = self._clean_target_list(
            self.target_device_ids,
            "target_device_ids",
        )
        if not self.pk and self.status != self.STATUS_DRAFT:
            raise ValidationError({"status": "A new release must start as a draft."})

    def save(self, *args, **kwargs):
        from .release_updates import (
            artifact_sha256_and_size,
            verify_artifact_integrity,
            verify_release_signature,
        )

        existing = None
        if self.pk:
            existing = type(self).objects.filter(pk=self.pk).first()
        replaced_artifact_name = ""

        desktop_version_validator(self.version)
        if int(self.build_number) < 1:
            raise ValidationError({"build_number": "Build number must be at least 1."})
        if self.channel not in dict(self.CHANNEL_CHOICES):
            raise ValidationError({"channel": "Unsupported release channel."})
        if self.mode not in dict(self.MODE_CHOICES):
            raise ValidationError({"mode": "Unsupported release mode."})
        if self.status not in dict(self.STATUS_CHOICES):
            raise ValidationError({"status": "Unsupported release status."})
        if existing is None and self.status != self.STATUS_DRAFT:
            raise ValidationError({"status": "A new release must start as a draft."})
        if (
            existing is not None
            and existing.status == self.STATUS_DRAFT
            and self.status not in {self.STATUS_DRAFT, self.STATUS_PUBLISHED}
        ):
            raise ValidationError(
                {"status": "A draft can only remain a draft or be published."}
            )
        self.target_offices = self._clean_target_list(
            self.target_offices,
            "target_offices",
        )
        self.target_device_ids = self._clean_target_list(
            self.target_device_ids,
            "target_device_ids",
        )
        self.signature_b64 = str(self.signature_b64 or "").strip()

        artifact_changed = bool(
            self.artifact
            and (
                existing is None
                or not getattr(self.artifact, "_committed", True)
                or self.artifact.name != existing.artifact.name
            )
        )
        if artifact_changed:
            if existing is not None and existing.status == self.STATUS_DRAFT:
                replaced_artifact_name = str(existing.artifact.name or "")
            self.original_filename = str(self.artifact.name).replace("\\", "/").rsplit("/", 1)[-1]
            self.artifact_sha256, self.artifact_size = artifact_sha256_and_size(
                self.artifact
            )
            max_bytes = max(1, int(settings.DESKTOP_RELEASE_MAX_BYTES))
            if self.artifact_size > max_bytes:
                raise ValidationError(
                    {"artifact": f"The release EXE exceeds the {max_bytes}-byte limit."}
                )
            source = getattr(self.artifact, "file", self.artifact)
            try:
                position = source.tell()
            except (AttributeError, OSError):
                position = 0
            try:
                source.seek(0)
                header = source.read(2)
            except (AttributeError, OSError) as exc:
                raise ValidationError(
                    {"artifact": "The release artifact could not be read."}
                ) from exc
            finally:
                try:
                    source.seek(position)
                except (AttributeError, OSError):
                    pass
            if header != b"MZ":
                raise ValidationError(
                    {"artifact": "The release artifact is not a Windows executable."}
                )
        elif existing is not None:
            # Hash and size are derived fields and never caller-controlled.
            self.original_filename = existing.original_filename
            self.artifact_sha256 = existing.artifact_sha256
            self.artifact_size = existing.artifact_size

        artifact_identity_fields = (
            "channel",
            "version",
            "build_number",
            "artifact",
            "original_filename",
            "artifact_sha256",
            "artifact_size",
            "signature_b64",
        )
        if existing is not None and existing.status in {
            self.STATUS_PUBLISHED,
            self.STATUS_REVOKED,
        }:
            immutable_fields = artifact_identity_fields
            if existing.status == self.STATUS_REVOKED:
                immutable_fields += (
                    "mode",
                    "target_offices",
                    "target_device_ids",
                )
            changed = [
                field
                for field in immutable_fields
                if getattr(self, field) != getattr(existing, field)
            ]
            if changed:
                raise ValidationError(
                    "This release's immutable fields cannot be changed; create a new release instead."
                )
            allowed_statuses = (
                {self.STATUS_PUBLISHED, self.STATUS_REVOKED}
                if existing.status == self.STATUS_PUBLISHED
                else {self.STATUS_REVOKED}
            )
            if self.status not in allowed_statuses:
                raise ValidationError({"status": "This release status transition is not allowed."})

        publishing = (
            self.status == self.STATUS_PUBLISHED
            and (existing is None or existing.status != self.STATUS_PUBLISHED)
        )
        if publishing:
            if existing is None:
                raise ValidationError({"status": "Save the release as a draft before publishing."})
            if type(self).objects.filter(
                channel=self.channel,
                build_number__gt=self.build_number,
            ).exclude(status=self.STATUS_DRAFT).exists():
                raise ValidationError(
                    {
                        "build_number": (
                            "A higher build has already been published or revoked "
                            "in this channel."
                        )
                    }
                )
            verify_artifact_integrity(self)
            verify_release_signature(self)

        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            expanded = set(update_fields)
            if artifact_changed:
                expanded.update(
                    {"artifact", "original_filename", "artifact_sha256", "artifact_size"}
                )
            kwargs["update_fields"] = tuple(expanded)
        result = super().save(*args, **kwargs)
        if replaced_artifact_name and replaced_artifact_name != self.artifact.name:
            storage = existing.artifact.storage
            transaction.on_commit(
                lambda: _delete_unreferenced_desktop_artifact(
                    storage,
                    replaced_artifact_name,
                )
            )
        return result


def _delete_unreferenced_desktop_artifact(storage, name: str) -> None:
    if not name or DesktopRelease.objects.filter(artifact=name).exists():
        return
    try:
        storage.delete(name)
    except (OSError, ValueError):
        logger.exception("Could not remove unused desktop release artifact %s", name)


@receiver(post_delete, sender=DesktopRelease)
def cleanup_deleted_draft_artifact(sender, instance, **kwargs) -> None:
    if instance.status != DesktopRelease.STATUS_DRAFT or not instance.artifact:
        return
    storage = instance.artifact.storage
    name = str(instance.artifact.name or "")
    transaction.on_commit(
        lambda: _delete_unreferenced_desktop_artifact(storage, name)
    )


class DesktopComponentRelease(models.Model):
    """A signed, independently deployable part of the OPTIX desktop app."""

    COMPONENT_UI = "ui"
    COMPONENT_ENGINE = "engine"
    COMPONENT_CONFIG = "config"
    COMPONENT_BRIDGE = "bridge"
    COMPONENT_BROWSER = "browser"
    COMPONENT_EXTENSION = "extension"
    COMPONENT_CHOICES = (
        (COMPONENT_UI, "UI bundle"),
        (COMPONENT_ENGINE, "Action engine"),
        (COMPONENT_CONFIG, "Application configuration"),
        (COMPONENT_BRIDGE, "Local Electron bridge"),
        (COMPONENT_BROWSER, "Browser package"),
        (COMPONENT_EXTENSION, "Browser extension"),
    )

    ACTIVATION_HOT = "hot"
    ACTIVATION_BRIDGE_RESTART = "bridge-restart"
    ACTIVATION_APP_RESTART = "app-restart"
    ACTIVATION_CHOICES = (
        (ACTIVATION_HOT, "Apply on Reload"),
        (ACTIVATION_BRIDGE_RESTART, "Apply after safe bridge restart"),
        (ACTIVATION_APP_RESTART, "Apply after OPTIX restart"),
    )

    CHANNEL_CHOICES = DesktopRelease.CHANNEL_CHOICES
    CHANNEL_PUBLIC = DesktopRelease.CHANNEL_PUBLIC
    CHANNEL_TESTING = DesktopRelease.CHANNEL_TESTING
    STATUS_CHOICES = DesktopRelease.STATUS_CHOICES
    STATUS_DRAFT = DesktopRelease.STATUS_DRAFT
    STATUS_PUBLISHED = DesktopRelease.STATUS_PUBLISHED
    STATUS_REVOKED = DesktopRelease.STATUS_REVOKED

    component = models.CharField(max_length=24, choices=COMPONENT_CHOICES)
    slot = models.CharField(
        max_length=64,
        default="default",
        validators=[component_version_validator],
        help_text=(
            "Use default for UI/engine/config/bridge; use the browser version or "
            "extension name for independently retained packages."
        ),
    )
    channel = models.CharField(
        max_length=16,
        choices=CHANNEL_CHOICES,
        default=CHANNEL_PUBLIC,
    )
    version = models.CharField(max_length=64, validators=[component_version_validator])
    build_number = models.PositiveBigIntegerField(
        validators=[MinValueValidator(1)],
        help_text="Monotonically increasing within this component and channel.",
    )
    activation = models.CharField(
        max_length=24,
        choices=ACTIVATION_CHOICES,
        default=ACTIVATION_HOT,
    )
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_DRAFT,
        editable=False,
    )
    target_offices = models.JSONField(default=list, blank=True)
    target_device_ids = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Non-secret activation data. UI/engine/bridge ZIPs use entry; browser "
            "ZIPs use browser_version."
        ),
    )
    artifact = models.FileField(
        storage=private_desktop_release_storage,
        upload_to=desktop_component_artifact_path,
        validators=[FileExtensionValidator(allowed_extensions=("zip", "json"))],
    )
    original_filename = models.CharField(max_length=255, blank=True, editable=False)
    artifact_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    artifact_size = models.PositiveBigIntegerField(default=0, editable=False)
    signature_b64 = models.TextField(
        blank=True,
        default="",
        help_text="Detached Ed25519 signature of the canonical component manifest.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="desktop_component_releases",
    )
    published_at = models.DateTimeField(blank=True, null=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("component", "-build_number", "-pk")
        constraints = [
            models.UniqueConstraint(
                fields=("component", "slot", "channel", "build_number"),
                name="unique_component_release_build",
            )
        ]
        indexes = [
            models.Index(
                fields=("channel", "status", "component", "slot", "-build_number"),
                name="component_release_lookup_idx",
            )
        ]

    def __str__(self) -> str:
        return f"{self.component}/{self.slot} {self.version} (build {self.build_number}, {self.channel})"

    def clean(self) -> None:
        super().clean()
        self.target_offices = DesktopRelease._clean_target_list(
            self.target_offices, "target_offices"
        )
        self.target_device_ids = DesktopRelease._clean_target_list(
            self.target_device_ids, "target_device_ids"
        )
        if not isinstance(self.metadata, dict):
            raise ValidationError({"metadata": "Enter a JSON object."})
        if not self.pk and self.status != self.STATUS_DRAFT:
            raise ValidationError({"status": "A new component must start as a draft."})

    def save(self, *args, **kwargs):
        from .release_updates import (
            artifact_sha256_and_size,
            verify_component_artifact_integrity,
            verify_component_signature,
        )

        existing = type(self).objects.filter(pk=self.pk).first() if self.pk else None
        if self.component not in dict(self.COMPONENT_CHOICES):
            raise ValidationError({"component": "Unsupported component type."})
        component_version_validator(self.slot)
        if self.channel not in dict(self.CHANNEL_CHOICES):
            raise ValidationError({"channel": "Unsupported release channel."})
        if self.activation not in dict(self.ACTIVATION_CHOICES):
            raise ValidationError({"activation": "Unsupported activation mode."})
        component_version_validator(self.version)
        if int(self.build_number) < 1:
            raise ValidationError({"build_number": "Build number must be at least 1."})
        self.target_offices = DesktopRelease._clean_target_list(
            self.target_offices, "target_offices"
        )
        self.target_device_ids = DesktopRelease._clean_target_list(
            self.target_device_ids, "target_device_ids"
        )
        if not isinstance(self.metadata, dict):
            raise ValidationError({"metadata": "Enter a JSON object."})
        self.signature_b64 = str(self.signature_b64 or "").strip()

        artifact_changed = bool(
            self.artifact
            and (
                existing is None
                or not getattr(self.artifact, "_committed", True)
                or self.artifact.name != existing.artifact.name
            )
        )
        replaced_artifact_name = ""
        if artifact_changed:
            if existing is not None and existing.status == self.STATUS_DRAFT:
                replaced_artifact_name = str(existing.artifact.name or "")
            self.original_filename = str(self.artifact.name).replace("\\", "/").rsplit("/", 1)[-1]
            self.artifact_sha256, self.artifact_size = artifact_sha256_and_size(self.artifact)
            if self.artifact_size > max(1, int(settings.DESKTOP_COMPONENT_MAX_BYTES)):
                raise ValidationError({"artifact": "The component package is too large."})
        elif existing is not None:
            self.original_filename = existing.original_filename
            self.artifact_sha256 = existing.artifact_sha256
            self.artifact_size = existing.artifact_size

        immutable_fields = (
            "component", "slot", "channel", "version", "build_number", "activation",
            "metadata", "artifact", "original_filename", "artifact_sha256",
            "artifact_size", "signature_b64",
        )
        if existing is not None and existing.status in {self.STATUS_PUBLISHED, self.STATUS_REVOKED}:
            if any(getattr(self, field) != getattr(existing, field) for field in immutable_fields):
                raise ValidationError(
                    "Published component identity and artifact fields are immutable."
                )
            allowed = (
                {self.STATUS_PUBLISHED, self.STATUS_REVOKED}
                if existing.status == self.STATUS_PUBLISHED
                else {self.STATUS_REVOKED}
            )
            if self.status not in allowed:
                raise ValidationError({"status": "This status transition is not allowed."})

        publishing = self.status == self.STATUS_PUBLISHED and (
            existing is None or existing.status != self.STATUS_PUBLISHED
        )
        if publishing:
            if existing is None:
                raise ValidationError({"status": "Save the component as a draft first."})
            if type(self).objects.filter(
                component=self.component,
                slot=self.slot,
                channel=self.channel,
                build_number__gt=self.build_number,
            ).exclude(status=self.STATUS_DRAFT).exists():
                raise ValidationError({"build_number": "A higher build is already published."})
            verify_component_artifact_integrity(self)
            verify_component_signature(self)

        update_fields = kwargs.get("update_fields")
        if update_fields is not None and artifact_changed:
            kwargs["update_fields"] = tuple(set(update_fields) | {
                "artifact", "original_filename", "artifact_sha256", "artifact_size"
            })
        result = super().save(*args, **kwargs)
        if replaced_artifact_name and replaced_artifact_name != self.artifact.name:
            storage = existing.artifact.storage
            transaction.on_commit(
                lambda: _delete_unreferenced_component_artifact(storage, replaced_artifact_name)
            )
        return result


def _delete_unreferenced_component_artifact(storage, name: str) -> None:
    if not name or DesktopComponentRelease.objects.filter(artifact=name).exists():
        return
    try:
        storage.delete(name)
    except (OSError, ValueError):
        logger.exception("Could not remove unused component artifact %s", name)


@receiver(post_delete, sender=DesktopComponentRelease)
def cleanup_deleted_component_artifact(sender, instance, **kwargs) -> None:
    if instance.status != DesktopComponentRelease.STATUS_DRAFT or not instance.artifact:
        return
    storage = instance.artifact.storage
    name = str(instance.artifact.name or "")
    transaction.on_commit(lambda: _delete_unreferenced_component_artifact(storage, name))


class DesktopRuntimeConfiguration(models.Model):
    """Small hot-reloadable UI/capability registry; never stores secrets."""

    channel = models.CharField(
        max_length=16,
        choices=DesktopRelease.CHANNEL_CHOICES,
        unique=True,
    )
    revision = models.PositiveBigIntegerField(default=1, validators=[MinValueValidator(1)])
    active = models.BooleanField(default=True)
    ui_config = models.JSONField(
        default=dict,
        help_text=(
            "Non-secret OPTIX UI data such as browsers, devices, labels, feature "
            "visibility and default selections. Changes apply through Reload."
        ),
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="desktop_runtime_configurations",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("channel",)

    def clean(self) -> None:
        super().clean()
        if not isinstance(self.ui_config, dict):
            raise ValidationError({"ui_config": "Enter a JSON object."})
        serialized = str(self.ui_config)
        forbidden = ("api_key", "token", "password", "secret", "credential")
        if any(word in serialized.casefold() for word in forbidden):
            raise ValidationError(
                {"ui_config": "Runtime UI configuration cannot contain credentials or secrets."}
            )

    def save(self, *args, **kwargs):
        if not isinstance(self.ui_config, dict):
            raise ValidationError({"ui_config": "Enter a JSON object."})
        if int(self.revision) < 1:
            raise ValidationError({"revision": "Revision must be at least 1."})
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"OPTIX {self.channel} runtime config (r{self.revision})"


class DesktopSecurityConfiguration(models.Model):
    """Global OPTIX activation and B1 bridge controls.

    Raw activation keys are one-way hashed.  The B1 bridge key has to be
    delivered to an authorized desktop at runtime, so it is encrypted with the
    same server-side encryption secret used by configuration bundles.
    """

    activation_required = models.BooleanField(
        default=False,
        help_text="When enabled, every OPTIX installation must present the current activation key.",
    )
    activation_key_hash = models.CharField(max_length=256, blank=True, editable=False)
    activation_key_ciphertext = models.TextField(blank=True, editable=False)
    activation_key_hint = models.CharField(max_length=16, blank=True, editable=False)
    activation_revision = models.PositiveBigIntegerField(default=1, validators=[MinValueValidator(1)])
    b1_enabled = models.BooleanField(
        default=False,
        help_text="Allow B1 (the local OPTIX Electron bridge) for activated clients.",
    )
    b1_key_ciphertext = models.TextField(blank=True, editable=False)
    b1_key_hint = models.CharField(max_length=16, blank=True, editable=False)
    b1_revision = models.PositiveBigIntegerField(default=1, validators=[MinValueValidator(1)])
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="desktop_security_configurations",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "OPTIX desktop security"
        verbose_name_plural = "OPTIX desktop security"

    def save(self, *args, **kwargs):
        if self.pk not in (None, 1):
            raise ValidationError("Only one global OPTIX desktop security record is allowed.")
        self.pk = 1
        return super().save(*args, **kwargs)

    def set_activation_key(self, value: str) -> None:
        value = str(value or "").strip()
        if len(value) < 16:
            raise ValidationError("The activation key must be at least 16 characters.")
        had_key = bool(self.activation_key_hash)
        self.activation_key_hash = make_password(value)
        self.activation_key_ciphertext = encrypt_text(value)
        self.activation_key_hint = f"…{value[-4:]}"
        self.activation_revision = (max(1, int(self.activation_revision or 0) + 1) if had_key else 1)

    def check_activation_key(self, value: str) -> bool:
        if not self.activation_key_hash:
            return False
        return check_password(str(value or ""), self.activation_key_hash)

    def get_activation_key(self) -> str:
        return decrypt_text(self.activation_key_ciphertext) if self.activation_key_ciphertext else ""

    def set_b1_key(self, value: str) -> None:
        value = str(value or "").strip()
        if len(value) < 24:
            raise ValidationError("The B1 bridge key must be at least 24 characters.")
        had_key = bool(self.b1_key_ciphertext)
        self.b1_key_ciphertext = encrypt_text(value)
        self.b1_key_hint = f"…{value[-4:]}"
        self.b1_revision = (max(1, int(self.b1_revision or 0) + 1) if had_key else 1)

    def get_b1_key(self) -> str:
        return decrypt_text(self.b1_key_ciphertext) if self.b1_key_ciphertext else ""

    def __str__(self) -> str:
        return "Global OPTIX desktop security"


class ProxyPoolTarget(models.Model):
    config_bundle = models.ForeignKey(ConfigBundle, on_delete=models.CASCADE, related_name="proxy_pool_targets")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    target_count = models.PositiveIntegerField(default=1000)
    replenish_below = models.PositiveIntegerField(default=200)
    active = models.BooleanField(default=True)
    refill_pending = models.BooleanField(default=False, editable=False)
    refill_requested_at = models.DateTimeField(blank=True, null=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("config_bundle", "provider_code", "country_code", "region", "city"), name="unique_proxy_pool_target")]


class ProxyPoolEntry(models.Model):
    target = models.ForeignKey(ProxyPoolTarget, on_delete=models.CASCADE, related_name="entries")
    proxy_fingerprint = models.CharField(max_length=64, unique=True)
    proxy_ciphertext = models.TextField(editable=False)
    state = models.CharField(max_length=16, default="available")
    exit_ip = models.GenericIPAddressField(blank=True, null=True)
    fraud_score = models.IntegerField(blank=True, null=True)
    reserved_client = models.ForeignKey(ClientAccess, on_delete=models.SET_NULL, blank=True, null=True, related_name="pool_entries")
    created_at = models.DateTimeField(auto_now_add=True)
    tested_at = models.DateTimeField(blank=True, null=True)
    reserved_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(
                fields=("target", "state"),
                name="poolentry_target_state_idx",
            ),
        ]

    def set_proxy(self, value: str) -> None:
        self.proxy_ciphertext = encrypt_text(value)

    def get_proxy(self) -> str:
        return decrypt_text(self.proxy_ciphertext)


class ProxyGenerationJob(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="proxy_jobs")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    submitted_count = models.PositiveSmallIntegerField(
        default=1,
        help_text="Number requested by the client before the server safety cap.",
    )
    requested_count = models.PositiveSmallIntegerField(default=1)
    candidate_count = models.PositiveSmallIntegerField(
        default=1,
        help_text=(
            "Maximum proxy candidates reserved for quality testing; profile "
            "counts continue to use requested_count."
        ),
    )
    ready_count = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=32, default="queued")
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ProxyInventoryAlert(models.Model):
    """Durable record of an app request that found insufficient inventory."""

    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="proxy_inventory_alerts",
    )
    dedupe_key = models.CharField(max_length=64, unique=True, editable=False)
    config_bundle = models.ForeignKey(
        ConfigBundle,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="proxy_inventory_alerts",
    )
    office_name = models.CharField(max_length=160, blank=True)
    system_number = models.CharField(max_length=80, blank=True)
    device_id = models.CharField(max_length=128, blank=True)
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    available_count = models.PositiveSmallIntegerField(default=0)
    requested_count = models.PositiveSmallIntegerField(default=1)
    occurrence_count = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=24, default="pending")
    provider_message_id = models.CharField(max_length=80, blank=True)
    error = models.TextField(blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    sent_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-last_seen_at", "-pk")
        indexes = [
            models.Index(
                fields=(
                    "config_bundle",
                    "provider_code",
                    "country_code",
                    "region",
                    "city",
                ),
                name="proxy_alert_scope_idx",
            ),
            models.Index(fields=("status", "last_seen_at"), name="proxy_alert_status_idx"),
        ]


class OfficeAuditRequest(ProxyGenerationJob):
    """Admin-facing request rows used by Office profile audit."""

    class Meta:
        proxy = True
        verbose_name = "Office audit request"
        verbose_name_plural = "Office audit requests"


class ProxyReservation(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="proxy_reservations")
    job = models.ForeignKey(ProxyGenerationJob, on_delete=models.SET_NULL, null=True, blank=True, related_name="reservations")
    pool_entry = models.ForeignKey(ProxyPoolEntry, on_delete=models.SET_NULL, null=True, blank=True, related_name="reservations")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    proxy_fingerprint = models.CharField(max_length=64, unique=True)
    proxy_ciphertext = models.TextField(blank=True, editable=False)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, blank=True)
    reserved_at = models.DateTimeField(auto_now_add=True)

    def set_proxy(self, value: str) -> None:
        self.proxy_ciphertext = encrypt_text(value)

    def get_proxy(self) -> str:
        return decrypt_text(self.proxy_ciphertext) if self.proxy_ciphertext else ""


class ProxyExitIPCooldown(models.Model):
    """Last globally accepted use of one normalized proxy exit IP."""

    # Deliberately unique only by IP: the cooldown spans every provider,
    # office and device rather than being scoped to a bundle or client.
    exit_ip = models.GenericIPAddressField(unique=True)
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="proxy_exit_ip_cooldowns",
    )
    job = models.ForeignKey(
        ProxyGenerationJob,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_ip_cooldowns",
    )
    reservation = models.ForeignKey(
        ProxyReservation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_ip_cooldowns",
    )
    provider_code = models.CharField(max_length=32, blank=True)
    fraud_score = models.IntegerField(blank=True, null=True)
    claimed_at = models.DateTimeField()
    available_after = models.DateTimeField(db_index=True)
    duplicate_attempts = models.PositiveIntegerField(default=0)
    last_duplicate_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-claimed_at", "exit_ip")
        verbose_name = "Proxy exit-IP cooldown"
        verbose_name_plural = "Proxy exit-IP cooldowns"


class ProfileCreateLease(models.Model):
    """Distributed guard for profile creation in one YS account/group.

    YS exposes a global environment list for an account.  A short-lived,
    database-backed lease prevents two desktop clients using the same account
    and browser group from taking each other's before/after profile snapshot.
    Expiry is intentional so a crashed client cannot block the group forever.
    """

    lease_key = models.CharField(max_length=180, unique=True)
    owner_token = models.CharField(max_length=96)
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.CASCADE,
        related_name="profile_create_leases",
    )
    group_id = models.CharField(max_length=64)
    requested_count = models.PositiveSmallIntegerField(default=1)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("expires_at",)


class ProfileCreateQueue(models.Model):
    """FIFO wait list for clients sharing one YS account/group."""

    STATUS_CHOICES = (
        ("queued", "Queued"),
        ("active", "Active"),
        ("completed", "Completed"),
        ("expired", "Expired"),
    )

    scope_key = models.CharField(max_length=180, db_index=True)
    request_token = models.CharField(max_length=96, unique=True)
    lease_token = models.CharField(max_length=96, blank=True, default="")
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.CASCADE,
        related_name="profile_create_queue",
    )
    group_id = models.CharField(max_length=64)
    requested_count = models.PositiveSmallIntegerField(default=1)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="queued")
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("created_at", "pk")
        indexes = [models.Index(fields=("scope_key", "status", "created_at"))]


class BrowserGroupMapping(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="browser_groups")
    browser_group_id = models.CharField(max_length=64)
    browser_group_name = models.CharField(max_length=160)
    internal_name = models.CharField(max_length=80, help_text="Your private management label.")
    is_default = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("client__office_name", "internal_name")
        constraints = [models.UniqueConstraint(fields=("client", "browser_group_id"), name="unique_client_browser_group")]

    def __str__(self) -> str:
        return f"{self.client} / {self.internal_name} ({self.browser_group_id})"


class ProfileActivity(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="profile_activity")
    job = models.ForeignKey(ProxyGenerationJob, on_delete=models.SET_NULL, null=True, blank=True, related_name="profile_activity")
    reservation = models.ForeignKey(ProxyReservation, on_delete=models.SET_NULL, null=True, blank=True, related_name="profile_activity")
    group_id = models.CharField(max_length=64, blank=True)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, blank=True)
    status = models.CharField(max_length=32)
    start_urls_json = models.TextField(blank=True)
    detail = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class OfficeProfileAudit(ProfileActivity):
    """Admin-facing view of lifecycle rows used by Office profile audit.

    This proxy deliberately shares the ProfileActivity table.  It gives the
    control staff a clearly named Django Admin module without duplicating any
    audit data or changing the desktop/API contract.
    """

    class Meta:
        proxy = True
        verbose_name = "Office profile audit log"
        verbose_name_plural = "Office profile audit logs"


class ProfileDomainActivity(models.Model):
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.CASCADE,
        related_name="profile_domain_activity",
    )
    job = models.ForeignKey(
        ProxyGenerationJob,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="profile_domain_activity",
    )
    reservation = models.ForeignKey(
        ProxyReservation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="profile_domain_activity",
    )
    session_id = models.CharField(max_length=64, db_index=True)
    group_id = models.CharField(max_length=64, blank=True, db_index=True)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, db_index=True)
    browser_id = models.CharField(max_length=64, blank=True)
    domain = models.CharField(max_length=253, db_index=True)
    first_visited_at = models.DateTimeField()
    last_visited_at = models.DateTimeField()
    visit_count = models.PositiveIntegerField(default=1)
    session_started_at = models.DateTimeField()
    session_ended_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-last_visited_at", "domain")
        verbose_name_plural = "Profile domain activity"
        constraints = [
            models.UniqueConstraint(
                fields=("client", "profile_id", "session_id", "domain"),
                name="unique_profile_session_domain",
            )
        ]

    def __str__(self) -> str:
        return f"{self.profile_id} / {self.domain}"


class OfficeAuditDomain(ProfileDomainActivity):
    """Admin-facing domain rows used by Office profile audit."""

    class Meta:
        proxy = True
        verbose_name = "Office audit domain log"
        verbose_name_plural = "Office audit domain logs"


class BootstrapAudit(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="audit_events",
    )
    observed_ip = models.GenericIPAddressField(blank=True, null=True, db_index=True)
    reported_ip = models.GenericIPAddressField(blank=True, null=True, db_index=True)
    device_id = models.CharField(max_length=128, blank=True, db_index=True)
    allowed = models.BooleanField(default=False)
    reason = models.CharField(max_length=80)
    app_version = models.CharField(max_length=40, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("allowed", "-id"),
                name="audit_allowed_id_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} / {self.observed_ip} / {self.reason}"
class MonitoredDomain(models.Model):
    domain = models.CharField(max_length=253, unique=True)
    label = models.CharField(max_length=120, blank=True, default="")
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="monitored_domains",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("domain",)
        verbose_name = "Monitored domain"
        verbose_name_plural = "Monitored domains"

    def __str__(self) -> str:
        return self.domain


class SubAdminAccount(models.Model):
    """A non-staff account for the separate sub-admin dashboard."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="subadmin_account",
    )
    display_name = models.CharField(max_length=120, blank=True, default="")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = "Sub-admin account"
        verbose_name_plural = "Sub-admin accounts"
        ordering = ("user__username",)

    def __str__(self) -> str:
        return self.display_name.strip() or self.user.get_username()

class SubAdminDomainExclusion(models.Model):
    """Exact domain hidden from one sub-admin account."""

    account = models.ForeignKey(
        SubAdminAccount,
        on_delete=models.CASCADE,
        related_name="domain_exclusions",
    )
    domain = models.CharField(max_length=253)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("domain",)
        verbose_name = "Sub-admin domain exclusion"
        verbose_name_plural = "Sub-admin domain exclusions"
        constraints = [
            models.UniqueConstraint(
                fields=("account", "domain"),
                name="unique_subadmin_domain_exclusion",
            )
        ]

    def save(self, *args, **kwargs):
        self.domain = self.domain.strip().casefold().rstrip(".")
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.account} / {self.domain}"

class SubAdminScopeExclusion(models.Model):
    """Office or browser-group scope hidden from one sub-admin account."""

    SCOPE_CHOICES = (
        ("office", "Office"),
        ("group", "Browser group"),
    )

    account = models.ForeignKey(
        SubAdminAccount,
        on_delete=models.CASCADE,
        related_name="scope_exclusions",
    )
    scope_type = models.CharField(max_length=16, choices=SCOPE_CHOICES)
    value = models.CharField(max_length=160)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("scope_type", "value")
        verbose_name = "Sub-admin scope exclusion"
        verbose_name_plural = "Sub-admin scope exclusions"
        constraints = [
            models.UniqueConstraint(
                fields=("account", "scope_type", "value"),
                name="unique_subadmin_scope_exclusion",
            )
        ]

    def save(self, *args, **kwargs):
        self.value = self.value.strip().casefold()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.account} / {self.scope_type}: {self.value}"
