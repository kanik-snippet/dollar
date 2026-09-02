from __future__ import annotations

import json
import re
import secrets
import zipfile
from pathlib import PurePosixPath
from urllib.parse import urlencode


from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html

from .models import (BootstrapAudit, ClientAccess, ConfigBundle, DesktopComponentRelease, DesktopRelease, DesktopRuntimeConfiguration, DesktopSecurityConfiguration, ExtensionPackage, MonitoredDomain, Provider, ProxyCountryFile, ProxyGenerationJob, ProxyInventoryAlert, OfficeAuditRequest, ProxyReservation, ProxyExitIPCooldown, ProfileActivity, OfficeProfileAudit, ProfileDomainActivity, OfficeAuditDomain, BrowserGroupMapping, ProxyPoolTarget, ProxyPoolEntry, ProxyRegionCatalog, ProxyCityCatalog, SubAdminAccount, SubAdminDomainExclusion, SubAdminScopeExclusion, ClientAccessIP, YSBridgeAgent, YSBridgeCommand)
from .release_updates import canonical_component_payload, canonical_release_payload
from .tasks import queue_refill_proxy_pool



def _profile_label(obj):
    """Show the readable profile name, with safe fallbacks for older rows."""
    candidates = (
        getattr(obj, "profile_name", ""),
        getattr(getattr(obj, "reservation", None), "profile_name", ""),
        getattr(getattr(obj, "client", None), "profile_name", ""),
        getattr(getattr(obj, "client", None), "name", ""),
        getattr(obj, "profile_id", ""),
    )
    for value in candidates:
        value = str(value or "").strip()
        if value:
            return value
    return "Unnamed"

_profile_label.short_description = "Profile"
_profile_label.admin_order_field = "profile_name"

class ProxyPoolGenerateForm(forms.Form):
    PROVIDER_CHOICES = (("P1", "P1"), ("P2", "P2"), ("P3", "P3"), ("P4", "P4"))
    provider_codes = forms.MultipleChoiceField(label="Providers", choices=PROVIDER_CHOICES, initial=("P1", "P2", "P3"), widget=forms.CheckboxSelectMultiple)
    country_codes = forms.CharField(label="Country codes", widget=forms.Textarea(attrs={"rows": 4, "placeholder": "US, UK, AU, CA"}), help_text="Comma, space or newline separated ISO-3166 alpha-2 codes.")
    config_bundle = forms.ModelChoiceField(label="Config bundle", queryset=ConfigBundle.objects.filter(active=True).order_by("name"))
    target_count = forms.IntegerField(min_value=1, max_value=5000, initial=1000)
    replenish_below = forms.IntegerField(min_value=0, max_value=4999, initial=200)
    purge_existing = forms.BooleanField(required=False, label="Purge existing pool entries first", help_text="Deletes generated pool entries for the selected providers/countries only; reservations and logs remain.")

    def clean_country_codes(self):
        values = []
        for token in re.split(r"[,;\s]+", self.cleaned_data["country_codes"].upper()):
            token = {"UK": "GB"}.get(token.strip(), token.strip())
            if not token:
                continue
            if not re.fullmatch(r"[A-Z]{2}", token):
                raise forms.ValidationError(f"Invalid country code: {token}")
            if token not in values:
                values.append(token)
        if not values:
            raise forms.ValidationError("Enter at least one country code.")
        return values
class ConfigBundleForm(forms.ModelForm):
    payload_json = forms.CharField(
        label="Encrypted configuration JSON",
        widget=forms.Textarea(attrs={"rows": 24, "cols": 100, "spellcheck": "false"}),
        help_text=(
            "Stored encrypted in PostgreSQL. It may contain every key formerly supplied "
            "through tubelight_config.txt. Never paste it into logs or support messages."
        ),
    )

    class Meta:
        model = ConfigBundle
        fields = (
            "name",
            "version",
            "active",
            "browser_group_id",
            "browser_group_name",
            "payload_json",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["payload_json"].initial = json.dumps(
                self.instance.get_payload(), indent=2, sort_keys=True
            )

    def clean_payload_json(self) -> dict:
        try:
            value = json.loads(self.cleaned_data["payload_json"])
        except json.JSONDecodeError as exc:
            raise forms.ValidationError(f"Invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise forms.ValidationError("Configuration must be a JSON object.")
        return value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_payload(self.cleaned_data["payload_json"])
        if commit:
            instance.save()
        return instance


class ProxyCountryFileForm(forms.ModelForm):
    proxy_text = forms.CharField(
        label="Encrypted proxy TXT content",
        widget=forms.Textarea(attrs={"rows": 24, "cols": 100, "spellcheck": "false"}),
        help_text="Content is returned exactly to an authorized app and stored encrypted.",
    )

    class Meta:
        model = ProxyCountryFile
        fields = (
            "provider",
            "country_code",
            "country_name",
            "version",
            "active",
            "proxy_text",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["proxy_text"].initial = self.instance.get_content()

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_content(self.cleaned_data["proxy_text"])
        if commit:
            instance.save()
        return instance


SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_CATALOG_FILES = 5_000
MAX_CATALOG_FILE_BYTES = 3 * 1024 * 1024
MAX_CATALOG_TOTAL_BYTES = 30 * 1024 * 1024


class CatalogZipUploadForm(forms.Form):
    catalog_zip = forms.FileField(
        label="Proxy catalog ZIP",
        help_text="Use P1/US.txt or proxy/P1/US__United States.txt paths inside the ZIP.",
    )

    def clean_catalog_zip(self):
        upload = self.cleaned_data["catalog_zip"]
        if not upload.name.lower().endswith(".zip"):
            raise forms.ValidationError("Upload a .zip file.")
        return upload


def _country_from_filename(filename: str) -> tuple[str, str]:
    stem = PurePosixPath(filename).stem.strip()
    if "__" in stem:
        country_code, country_name = stem.split("__", 1)
    else:
        country_code = re.sub(r"[^A-Za-z0-9_-]+", "-", stem).strip("-")
        country_name = stem.replace("_", " ").replace("-", " ").strip().title()
    if not SAFE_ID.fullmatch(country_code):
        raise ValueError(f"Unsafe country code: {filename}")
    return country_code, country_name or country_code


@transaction.atomic
def import_catalog_zip(upload, only_provider: str | None = None) -> tuple[int, int]:
    """Import a browser ZIP with batched writes, replacing matching country rows."""
    total_size = 0
    records: dict[tuple[str, str], tuple[str, str]] = {}
    try:
        archive = zipfile.ZipFile(upload)
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc

    with archive:
        entries = [
            info for info in archive.infolist()
            if not info.is_dir() and info.filename.lower().endswith(".txt")
        ]
        if not entries:
            raise ValueError("The ZIP does not contain any TXT files.")
        if len(entries) > MAX_CATALOG_FILES:
            raise ValueError("Too many TXT files in one ZIP.")
        for info in entries:
            if info.file_size > MAX_CATALOG_FILE_BYTES:
                raise ValueError(f"TXT file is too large: {info.filename}")
            total_size += info.file_size
            if total_size > MAX_CATALOG_TOTAL_BYTES:
                raise ValueError("Total ZIP TXT content is too large.")
            parts = [
                part for part in PurePosixPath(info.filename).parts
                if part not in {"", ".", ".."}
            ]
            if only_provider:
                if len(parts) >= 2 and parts[-2] == only_provider:
                    provider_code, filename = only_provider, parts[-1]
                elif len(parts) == 1:
                    provider_code, filename = only_provider, parts[-1]
                else:
                    continue
            else:
                if len(parts) < 2:
                    raise ValueError(f"Use P1/US.txt style paths: {info.filename}")
                provider_code, filename = parts[-2], parts[-1]
            if not SAFE_ID.fullmatch(provider_code):
                raise ValueError(f"Unsafe provider code: {provider_code}")
            country_code, country_name = _country_from_filename(filename)
            try:
                content = archive.read(info).decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(f"TXT must be UTF-8: {info.filename}") from exc
            records[(provider_code, country_code)] = (country_name, content)

    if not records:
        raise ValueError("No TXT files matched this provider.")

    provider_codes = sorted({provider_code for provider_code, _ in records})
    existing_providers = {item.code: item for item in Provider.objects.filter(code__in=provider_codes)}
    Provider.objects.bulk_create(
        [
            Provider(code=code, display_name=code, display_order=0, active=True)
            for code in provider_codes if code not in existing_providers
        ],
        ignore_conflicts=True,
        batch_size=100,
    )
    Provider.objects.filter(code__in=provider_codes).update(active=True)
    providers = {item.code: item for item in Provider.objects.filter(code__in=provider_codes)}

    provider_ids = [item.pk for item in providers.values()]
    country_codes = {country_code for _, country_code in records}
    existing_rows = {
        (item.provider_id, item.country_code): item
        for item in ProxyCountryFile.objects.filter(
            provider_id__in=provider_ids,
            country_code__in=country_codes,
        )
    }
    now = timezone.now()
    new_rows: list[ProxyCountryFile] = []
    changed_rows: list[ProxyCountryFile] = []
    replaced = 0
    for (provider_code, country_code), (country_name, content) in records.items():
        provider = providers[provider_code]
        row = existing_rows.get((provider.pk, country_code))
        if row is None:
            row = ProxyCountryFile(
                provider=provider,
                country_code=country_code,
                country_name=country_name,
                active=True,
            )
            row.set_content(content)
            new_rows.append(row)
        else:
            row.version += 1
            row.country_name = country_name
            row.active = True
            row.updated_at = now
            row.set_content(content)
            changed_rows.append(row)
            replaced += 1
    if new_rows:
        ProxyCountryFile.objects.bulk_create(new_rows, batch_size=100)
    if changed_rows:
        ProxyCountryFile.objects.bulk_update(
            changed_rows,
            ["country_name", "version", "active", "content_ciphertext", "content_sha256", "updated_at"],
            batch_size=100,
        )
    return len(records), replaced


class SubAdminScopeExclusionForm(forms.ModelForm):
    class Meta:
        model = SubAdminScopeExclusion
        fields = ("account", "scope_type", "value", "active")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        offices = list(
            ClientAccess.objects.exclude(office_name="")
            .values_list("office_name", flat=True)
            .distinct().order_by("office_name")
        )
        group_values = set(
            ProfileDomainActivity.objects.exclude(group_id="")
            .values_list("group_id", flat=True).distinct()
        )
        group_values.update(
            BrowserGroupMapping.objects.exclude(browser_group_id="")
            .values_list("browser_group_id", flat=True).distinct()
        )
        self._scope_values = {
            "office": {str(value).casefold(): str(value) for value in offices},
            "group": {str(value).casefold(): str(value) for value in group_values},
        }
        choices = [("", "Select an existing office or browser group")]
        choices.append(("Offices", [(f"office::{value}", value) for value in offices]))
        choices.append(("Browser groups", [(f"group::{value}", value) for value in sorted(group_values)]))
        if "scope_type" in self.fields:
            self.fields["scope_type"].widget = forms.HiddenInput()
        self.fields["value"] = forms.ChoiceField(
            label="Office / browser group",
            choices=choices,
            help_text="Choose an existing value; its type is assigned automatically.",
        )
        if self.instance.pk:
            self.initial["value"] = f"{self.instance.scope_type}::{self.instance.value}"

    def clean(self):
        cleaned = super().clean()
        selected = str(cleaned.get("value") or "").strip()
        scope_type, separator, value = selected.partition("::")
        if not separator:
            raw = selected.casefold()
            matches = [
                (kind, values[raw])
                for kind, values in self._scope_values.items()
                if raw in values
            ]
            if len(matches) == 1:
                scope_type, value = matches[0]
        if scope_type not in {"office", "group"} or not value:
            self.add_error(
                "value",
                "Select one of the existing Office or Browser group options.",
            )
            raise forms.ValidationError("The selected Office/Group could not be identified.")
        cleaned["scope_type"] = scope_type
        cleaned["value"] = value
        return cleaned

    def validate_unique(self):
        """Treat submitting an existing exclusion as an idempotent update."""
        try:
            super().validate_unique()
        except ValidationError:
            account = self.cleaned_data.get("account")
            scope_type = self.cleaned_data.get("scope_type")
            value = self.cleaned_data.get("value")
            if not account or not scope_type or not value:
                raise
            duplicate = SubAdminScopeExclusion.objects.filter(
                account=account, scope_type=scope_type, value=value
            ).exclude(pk=self.instance.pk).exists()
            if not duplicate:
                raise

    def save(self, commit=True):
        account = self.cleaned_data.get("account")
        scope_type = self.cleaned_data.get("scope_type")
        value = self.cleaned_data.get("value")
        if account and scope_type and value and not self.instance.pk:
            existing = SubAdminScopeExclusion.objects.filter(
                account=account, scope_type=scope_type, value=value
            ).first()
            if existing:
                self.instance = existing
        return super().save(commit=commit)

class SubAdminDomainExclusionInline(admin.TabularInline):
    model = SubAdminDomainExclusion
    extra = 1
    fields = ("domain", "active")


class SubAdminScopeExclusionInline(admin.TabularInline):
    model = SubAdminScopeExclusion
    form = SubAdminScopeExclusionForm
    extra = 1
    fields = ("scope_type", "value", "active")


@admin.register(SubAdminAccount)
class SubAdminAccountAdmin(admin.ModelAdmin):
    list_display = ("user", "display_name", "active", "last_login_at", "created_at")
    list_filter = ("active",)
    search_fields = ("user__username", "user__email", "display_name")
    autocomplete_fields = ("user",)
    readonly_fields = ("created_at", "last_login_at")
    inlines = (SubAdminDomainExclusionInline, SubAdminScopeExclusionInline)


@admin.register(SubAdminDomainExclusion)
class SubAdminDomainExclusionAdmin(admin.ModelAdmin):
    list_display = ("account", "domain", "active", "created_at")
    list_filter = ("active", "account")
    search_fields = ("domain", "account__user__username", "account__display_name")


@admin.register(SubAdminScopeExclusion)
class SubAdminScopeExclusionAdmin(admin.ModelAdmin):
    form = SubAdminScopeExclusionForm
    fields = ("account", "scope_type", "value", "active")
    autocomplete_fields = ("account",)
    list_display = ("account", "scope_type", "value", "active", "created_at")
    list_filter = ("scope_type", "active", "account")
    search_fields = ("value", "account__user__username", "account__display_name")

@admin.register(ConfigBundle)
class ConfigBundleAdmin(admin.ModelAdmin):
    form = ConfigBundleForm
    list_display = (
        "name",
        "version",
        "browser_group_name",
        "browser_group_id",
        "active",
        "updated_at",
    )
    list_filter = ("active",)
    search_fields = ("name", "browser_group_name", "browser_group_id")


class ClientAccessIPInline(admin.TabularInline):
    model = ClientAccessIP
    extra = 1
    fields = ("ipv4", "active", "created_at")
    readonly_fields = ("created_at",)


@admin.register(ClientAccessIP)
class ClientAccessIPAdmin(admin.ModelAdmin):
    list_display = ("client", "ipv4", "active", "created_at")
    list_filter = ("active", "client__office_name")
    search_fields = ("ipv4", "client__name", "client__device_id", "client__office_name")

@admin.register(ClientAccess)
class ClientAccessAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "ipv4",
        "device_id",
        "office_name",
        "system_number",
        "profile_name",
        "config_bundle",
        "release_channel",
        "activation_mode",
        "active",
        "last_seen_at",
    )
    list_filter = ("active", "release_channel", "activation_mode", "office_name", "config_bundle")
    list_editable = ("activation_mode",)
    search_fields = (
        "name",
        "ipv4",
        "device_id",
        "office_name",
        "system_number",
        "profile_name",
    )
    inlines = (ClientAccessIPInline,)


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    change_list_template = "admin/control/provider/change_list.html"
    list_display = ("code", "display_name", "display_order", "active", "country_files_link", "upload_countries_link")
    list_editable = ("display_name", "display_order", "active")

    def get_urls(self):
        custom = [
            path("upload-catalog/", self.admin_site.admin_view(self.upload_catalog_view), name="control_provider_upload_catalog"),
            path("<int:provider_id>/upload-catalog/", self.admin_site.admin_view(self.upload_catalog_view), name="control_provider_upload_countries"),
        ]
        return custom + super().get_urls()

    @admin.display(description="Countries")
    def country_files_link(self, obj):
        url = reverse("admin:control_proxycountryfile_changelist") + f"?provider__id__exact={obj.pk}"
        return format_html('<a href="{}">View country TXT files</a>', url)

    @admin.display(description="Upload")
    def upload_countries_link(self, obj):
        url = reverse("admin:control_provider_upload_countries", args=(obj.pk,))
        return format_html('<a class="button" href="{}">Upload / replace</a>', url)

    def upload_catalog_view(self, request: HttpRequest, provider_id: int | None = None) -> HttpResponse:
        provider = get_object_or_404(Provider, pk=provider_id) if provider_id is not None else None
        if request.method == "POST":
            form = CatalogZipUploadForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    imported, replaced = import_catalog_zip(form.cleaned_data["catalog_zip"], provider.code if provider else None)
                except ValueError as exc:
                    form.add_error("catalog_zip", str(exc))
                else:
                    messages.success(request, f"Imported {imported} TXT file(s); replaced {replaced} existing country file(s).")
                    return redirect("admin:control_provider_changelist" if provider is None else reverse("admin:control_proxycountryfile_changelist") + f"?provider__id__exact={provider.pk}")
        else:
            form = CatalogZipUploadForm()
        rows = provider.country_files.all() if provider else ()
        return TemplateResponse(request, "admin/control/provider/upload_catalog.html", {**self.admin_site.each_context(request), "title": "Upload proxy catalog" if provider is None else f"Upload countries for {provider.code}", "form": form, "provider": provider, "rows": rows})


@admin.register(ProxyCountryFile)
class ProxyCountryFileAdmin(admin.ModelAdmin):
    form = ProxyCountryFileForm
    list_display = (
        "provider",
        "country_code",
        "country_name",
        "version",
        "active",
        "updated_at",
    )
    list_filter = ("provider", "active")
    search_fields = ("provider__code", "country_code", "country_name")


@admin.register(ProxyRegionCatalog)
class ProxyRegionCatalogAdmin(admin.ModelAdmin):
    list_display = (
        "provider", "country_code", "region_code", "region_name", "source", "active"
    )
    list_filter = ("provider", "country_code", "source", "active")
    search_fields = ("provider__code", "country_code", "region_code", "region_name")


@admin.register(ProxyCityCatalog)
class ProxyCityCatalogAdmin(admin.ModelAdmin):
    list_display = (
        "provider", "account_key", "country_code", "region_code", "city_name", "source", "active"
    )
    list_filter = ("provider", "country_code", "source", "active")
    search_fields = ("provider__code", "account_key", "country_code", "region_code", "city_name")


class ExtensionPackageForm(forms.ModelForm):
    package_zip = forms.FileField(required=False, label="Extension ZIP package")

    class Meta:
        model = ExtensionPackage
        fields = ("name", "filename", "version", "is_top", "status", "package_zip")

    def clean_package_zip(self):
        upload = self.cleaned_data.get("package_zip")
        if upload is not None and not upload.name.lower().endswith(".zip"):
            raise forms.ValidationError("Extension package must be a ZIP file.")
        if upload is not None and upload.size > 20 * 1024 * 1024:
            raise forms.ValidationError("Extension ZIP must be 20 MB or smaller.")
        if not self.instance.pk and upload is None:
            raise forms.ValidationError("Upload an extension ZIP package.")
        return upload

    def save(self, commit=True):
        instance = super().save(commit=False)
        upload = self.cleaned_data.get("package_zip")
        if upload is not None:
            instance.filename = upload.name
            instance.set_package(upload.read())
        if commit:
            instance.save()
        return instance


@admin.register(ExtensionPackage)
class ExtensionPackageAdmin(admin.ModelAdmin):
    form = ExtensionPackageForm
    list_display = ("name", "filename", "version", "status", "is_top", "updated_at")
    list_editable = ("status", "is_top")
    readonly_fields = ("package_sha256", "updated_at")


class DesktopReleaseForm(forms.ModelForm):
    class Meta:
        model = DesktopRelease
        fields = (
            "channel",
            "version",
            "build_number",
            "mode",
            "target_offices",
            "target_device_ids",
            "artifact",
            "signature_b64",
        )
        widgets = {
            "target_offices": forms.Textarea(attrs={"rows": 4, "cols": 80}),
            "target_device_ids": forms.Textarea(attrs={"rows": 4, "cols": 80}),
            "signature_b64": forms.Textarea(attrs={"rows": 4, "cols": 100}),
            # ClearableFileInput reads FieldFile.url while rendering. Private
            # release storage intentionally has no URL, and the adjacent
            # original_filename field provides the current-file label.
            "artifact": forms.FileInput(),
        }

    def clean_artifact(self):
        upload = self.cleaned_data.get("artifact")
        if not self.instance.pk and not upload:
            raise forms.ValidationError("Upload a Windows EXE release artifact.")
        if not upload or getattr(upload, "_committed", False):
            return upload
        if not str(upload.name or "").lower().endswith(".exe"):
            raise forms.ValidationError("The release artifact must be an EXE file.")
        max_bytes = max(1, int(settings.DESKTOP_RELEASE_MAX_BYTES))
        if int(upload.size) > max_bytes:
            raise forms.ValidationError(
                f"The EXE must be {max_bytes // (1024 * 1024)} MB or smaller."
            )
        position = upload.tell()
        try:
            upload.seek(0)
            if upload.read(2) != b"MZ":
                raise forms.ValidationError(
                    "The uploaded file does not have a Windows executable header."
                )
        finally:
            upload.seek(position)
        return upload


@admin.register(DesktopRelease)
class DesktopReleaseAdmin(admin.ModelAdmin):
    form = DesktopReleaseForm
    actions = ("publish_releases", "revoke_releases")
    list_display = (
        "version",
        "build_number",
        "channel",
        "mode",
        "status",
        "scope_summary",
        "artifact_size",
        "published_at",
    )
    list_filter = ("channel", "mode", "status")
    search_fields = (
        "version",
        "artifact_sha256",
        "original_filename",
        "target_offices",
        "target_device_ids",
    )
    readonly_fields = (
        "status",
        "original_filename",
        "artifact_sha256",
        "artifact_size",
        "artifact_reference",
        "canonical_payload",
        "created_by",
        "published_at",
        "created_at",
        "updated_at",
    )
    fieldsets = (
        (
            "Release identity",
            {
                "fields": (
                    "channel",
                    "version",
                    "build_number",
                    "artifact",
                    "original_filename",
                    "artifact_sha256",
                    "artifact_size",
                )
            },
        ),
        (
            "Rollout",
            {"fields": ("mode", "target_offices", "target_device_ids", "status")},
        ),
        (
            "Offline Ed25519 signature",
            {
                "fields": ("canonical_payload", "signature_b64"),
                "description": (
                    "Save the draft first, sign the exact canonical payload with the "
                    "offline release key, paste the Base64 signature, save, then use "
                    "the Publish action."
                ),
            },
        ),
        (
            "Audit",
            {
                "fields": ("created_by", "published_at", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)
        return actions

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if obj and obj.status in {
            DesktopRelease.STATUS_PUBLISHED,
            DesktopRelease.STATUS_REVOKED,
        }:
            fields.extend(
                (
                    "channel",
                    "version",
                    "build_number",
                    "signature_b64",
                )
            )
        if obj and obj.status == DesktopRelease.STATUS_REVOKED:
            fields.extend(("mode", "target_offices", "target_device_ids"))
        return tuple(dict.fromkeys(fields))

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        if not obj or obj.status == DesktopRelease.STATUS_DRAFT:
            return fieldsets
        private_fieldsets = []
        for title, options in fieldsets:
            copied = dict(options)
            copied["fields"] = tuple(
                "artifact_reference" if field == "artifact" else field
                for field in options.get("fields", ())
            )
            private_fieldsets.append((title, copied))
        return tuple(private_fieldsets)

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    def has_delete_permission(self, request, obj=None):
        if obj is not None and obj.status != DesktopRelease.STATUS_DRAFT:
            return False
        return super().has_delete_permission(request, obj)

    @admin.display(description="Scope")
    def scope_summary(self, obj):
        offices = len(obj.target_offices or [])
        devices = len(obj.target_device_ids or [])
        if not offices and not devices:
            return "All assigned devices"
        return f"{offices or 'all'} office(s), {devices or 'all'} device(s)"

    @admin.display(description="Private release artifact")
    def artifact_reference(self, obj):
        if not obj or not obj.artifact:
            return "No artifact"
        return obj.original_filename or "Stored private executable"

    @admin.display(description="Canonical signed payload")
    def canonical_payload(self, obj):
        if not obj or not obj.pk:
            return "Save the draft to calculate its SHA-256 and canonical payload."
        return canonical_release_payload(obj).decode("utf-8")

    @admin.action(description="Publish selected signed release(s)")
    def publish_releases(self, request, queryset):
        published = 0
        for selected in queryset:
            try:
                with transaction.atomic():
                    release = DesktopRelease.objects.select_for_update().get(
                        pk=selected.pk
                    )
                    if release.status != DesktopRelease.STATUS_DRAFT:
                        raise ValidationError("Only draft releases can be published.")
                    release.status = DesktopRelease.STATUS_PUBLISHED
                    release.published_at = timezone.now()
                    release.save(
                        update_fields=("status", "published_at", "updated_at")
                    )
                published += 1
            except (OSError, ValidationError) as exc:
                self.message_user(
                    request,
                    f"Release {selected}: {exc}",
                    level=messages.ERROR,
                )
        if published:
            self.message_user(
                request,
                f"Published {published} signed desktop release(s).",
                level=messages.SUCCESS,
            )

    @admin.action(description="Revoke selected published release(s)")
    def revoke_releases(self, request, queryset):
        revoked = 0
        for selected in queryset:
            try:
                with transaction.atomic():
                    release = DesktopRelease.objects.select_for_update().get(
                        pk=selected.pk
                    )
                    if release.status != DesktopRelease.STATUS_PUBLISHED:
                        raise ValidationError("Only published releases can be revoked.")
                    release.status = DesktopRelease.STATUS_REVOKED
                    release.save(update_fields=("status", "updated_at"))
                revoked += 1
            except ValidationError as exc:
                self.message_user(
                    request,
                    f"Release {selected}: {exc}",
                    level=messages.ERROR,
                )
        if revoked:
            self.message_user(
                request,
                f"Revoked {revoked} desktop release(s).",
                level=messages.SUCCESS,
            )


class DesktopComponentReleaseForm(forms.ModelForm):
    class Meta:
        model = DesktopComponentRelease
        fields = (
            "component", "slot", "channel", "version", "build_number", "activation",
            "target_offices", "target_device_ids", "metadata", "artifact",
            "signature_b64",
        )
        widgets = {
            "target_offices": forms.Textarea(attrs={"rows": 3, "cols": 80}),
            "target_device_ids": forms.Textarea(attrs={"rows": 3, "cols": 80}),
            "metadata": forms.Textarea(attrs={"rows": 8, "cols": 100}),
            "signature_b64": forms.Textarea(attrs={"rows": 4, "cols": 100}),
            "artifact": forms.FileInput(),
        }

    def clean_artifact(self):
        upload = self.cleaned_data.get("artifact")
        if not self.instance.pk and not upload:
            raise forms.ValidationError("Upload a ZIP or JSON component artifact.")
        if not upload or getattr(upload, "_committed", False):
            return upload
        suffix = str(upload.name or "").casefold().rpartition(".")[2]
        if suffix not in {"zip", "json"}:
            raise forms.ValidationError("Component artifacts must be ZIP or JSON files.")
        if int(upload.size) > max(1, int(settings.DESKTOP_COMPONENT_MAX_BYTES)):
            raise forms.ValidationError("The component artifact exceeds the configured limit.")
        if suffix == "json":
            position = upload.tell()
            try:
                upload.seek(0)
                parsed = json.loads(upload.read().decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise ValueError("root must be an object")
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                raise forms.ValidationError("The JSON component is invalid.") from exc
            finally:
                upload.seek(position)
        else:
            position = upload.tell()
            try:
                upload.seek(0)
                with zipfile.ZipFile(upload) as archive:
                    for member in archive.infolist():
                        safe = PurePosixPath(member.filename.replace("\\", "/"))
                        if safe.is_absolute() or ".." in safe.parts:
                            raise forms.ValidationError("ZIP contains an unsafe path.")
                        if (member.external_attr >> 16) & 0o170000 == 0o120000:
                            raise forms.ValidationError("ZIP symbolic links are not allowed.")
            except zipfile.BadZipFile as exc:
                raise forms.ValidationError("The component ZIP is invalid.") from exc
            finally:
                upload.seek(position)
        return upload


@admin.register(DesktopComponentRelease)
class DesktopComponentReleaseAdmin(admin.ModelAdmin):
    form = DesktopComponentReleaseForm
    actions = ("publish_components", "revoke_components")
    list_display = (
        "component", "slot", "version", "build_number", "channel", "activation",
        "status", "scope_summary", "artifact_size", "published_at",
    )
    list_filter = ("component", "channel", "activation", "status")
    search_fields = (
        "version", "artifact_sha256", "original_filename", "target_offices",
        "target_device_ids",
    )
    readonly_fields = (
        "status", "original_filename", "artifact_sha256", "artifact_size",
        "artifact_reference", "canonical_payload", "created_by", "published_at",
        "created_at", "updated_at",
    )
    fieldsets = (
        ("Component", {"fields": (
            "component", "slot", "channel", "version", "build_number", "activation",
            "artifact", "original_filename", "artifact_sha256", "artifact_size",
        )}),
        ("Rollout scope", {"fields": (
            "target_offices", "target_device_ids", "metadata", "status",
        )}),
        ("Offline Ed25519 signature", {"fields": (
            "canonical_payload", "signature_b64",
        )}),
        ("Audit", {"fields": (
            "created_by", "published_at", "created_at", "updated_at",
        ), "classes": ("collapse",)}),
    )

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)
        return actions

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if obj and obj.status != DesktopComponentRelease.STATUS_DRAFT:
            fields.extend((
                "component", "slot", "channel", "version", "build_number", "activation",
                "metadata", "signature_b64",
            ))
        if obj and obj.status == DesktopComponentRelease.STATUS_REVOKED:
            fields.extend(("target_offices", "target_device_ids"))
        return tuple(dict.fromkeys(fields))

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        if not obj or obj.status == DesktopComponentRelease.STATUS_DRAFT:
            return fieldsets
        result = []
        for title, options in fieldsets:
            copied = dict(options)
            copied["fields"] = tuple(
                "artifact_reference" if field == "artifact" else field
                for field in options.get("fields", ())
            )
            result.append((title, copied))
        return tuple(result)

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    def has_delete_permission(self, request, obj=None):
        if obj is not None and obj.status != DesktopComponentRelease.STATUS_DRAFT:
            return False
        return super().has_delete_permission(request, obj)

    @admin.display(description="Scope")
    def scope_summary(self, obj):
        offices = len(obj.target_offices or [])
        devices = len(obj.target_device_ids or [])
        return "All assigned devices" if not offices and not devices else (
            f"{offices or 'all'} office(s), {devices or 'all'} device(s)"
        )

    @admin.display(description="Private component artifact")
    def artifact_reference(self, obj):
        return obj.original_filename if obj and obj.artifact else "No artifact"

    @admin.display(description="Canonical signed payload")
    def canonical_payload(self, obj):
        if not obj or not obj.pk:
            return "Save the draft to calculate its SHA-256 and canonical payload."
        return canonical_component_payload(obj).decode("utf-8")

    @admin.action(description="Publish selected signed component(s)")
    def publish_components(self, request, queryset):
        published = 0
        for selected in queryset:
            try:
                with transaction.atomic():
                    release = DesktopComponentRelease.objects.select_for_update().get(pk=selected.pk)
                    if release.status != DesktopComponentRelease.STATUS_DRAFT:
                        raise ValidationError("Only draft components can be published.")
                    release.status = DesktopComponentRelease.STATUS_PUBLISHED
                    release.published_at = timezone.now()
                    release.save(update_fields=("status", "published_at", "updated_at"))
                published += 1
            except (OSError, ValidationError) as exc:
                self.message_user(request, f"Component {selected}: {exc}", level=messages.ERROR)
        if published:
            self.message_user(request, f"Published {published} signed component(s).", level=messages.SUCCESS)

    @admin.action(description="Revoke selected published component(s)")
    def revoke_components(self, request, queryset):
        revoked = 0
        for selected in queryset:
            try:
                with transaction.atomic():
                    release = DesktopComponentRelease.objects.select_for_update().get(pk=selected.pk)
                    if release.status != DesktopComponentRelease.STATUS_PUBLISHED:
                        raise ValidationError("Only published components can be revoked.")
                    release.status = DesktopComponentRelease.STATUS_REVOKED
                    release.save(update_fields=("status", "updated_at"))
                revoked += 1
            except ValidationError as exc:
                self.message_user(request, f"Component {selected}: {exc}", level=messages.ERROR)
        if revoked:
            self.message_user(request, f"Revoked {revoked} component(s).", level=messages.SUCCESS)


@admin.register(DesktopRuntimeConfiguration)
class DesktopRuntimeConfigurationAdmin(admin.ModelAdmin):
    list_display = ("channel", "revision", "active", "updated_at", "updated_by")
    list_editable = ("active",)
    readonly_fields = ("updated_by", "created_at", "updated_at")
    fields = ("channel", "revision", "active", "ui_config", "updated_by", "created_at", "updated_at")

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        if change and "ui_config" in form.changed_data and "revision" not in form.changed_data:
            obj.revision = int(obj.revision) + 1
        super().save_model(request, obj, form, change)


class DesktopSecurityConfigurationForm(forms.ModelForm):
    activation_key = forms.CharField(
        required=False,
        min_length=16,
        max_length=512,
        widget=forms.PasswordInput(render_value=False),
        help_text="Leave blank to keep the current key. Entering a value rotates activation immediately.",
    )
    b1_bridge_key = forms.CharField(
        required=False,
        min_length=24,
        max_length=512,
        widget=forms.PasswordInput(render_value=False),
        help_text="Leave blank to keep the current B1 bridge key. Entering a value rotates B1 immediately.",
    )
    generate_activation_key = forms.BooleanField(
        required=False,
        label="Generate and rotate activation key",
        help_text="Creates a strong key. Copy the one-time confirmation after saving before leaving this page.",
    )
    generate_b1_bridge_key = forms.BooleanField(
        required=False,
        label="Generate and rotate B1 bridge key",
        help_text="Creates a strong B1 key. Copy the one-time confirmation after saving before leaving this page.",
    )

    class Meta:
        model = DesktopSecurityConfiguration
        fields = ("activation_required", "b1_enabled")

    def clean(self):
        cleaned = super().clean()
        activation_key = str(cleaned.get("activation_key") or "").strip()
        b1_key = str(cleaned.get("b1_bridge_key") or "").strip()
        generate_activation = bool(cleaned.get("generate_activation_key"))
        generate_b1 = bool(cleaned.get("generate_b1_bridge_key"))
        if activation_key and generate_activation:
            self.add_error("generate_activation_key", "Use either a manually entered key or Generate, not both.")
        if b1_key and generate_b1:
            self.add_error("generate_b1_bridge_key", "Use either a manually entered key or Generate, not both.")
        if cleaned.get("activation_required") and not (activation_key or generate_activation or self.instance.activation_key_hash):
            self.add_error("activation_key", "Enter the first activation key before enabling activation.")
        if cleaned.get("b1_enabled") and not (b1_key or generate_b1 or self.instance.b1_key_ciphertext):
            self.add_error("b1_bridge_key", "Enter the first B1 bridge key before enabling B1.")
        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)
        activation_key = str(self.cleaned_data.get("activation_key") or "").strip()
        b1_key = str(self.cleaned_data.get("b1_bridge_key") or "").strip()
        self.generated_activation_key = ""
        self.generated_b1_bridge_key = ""
        if self.cleaned_data.get("generate_activation_key"):
            self.generated_activation_key = f"OPTIX-ACT-{secrets.token_urlsafe(32)}"
            activation_key = self.generated_activation_key
        if self.cleaned_data.get("generate_b1_bridge_key"):
            self.generated_b1_bridge_key = f"OPTIX-B1-{secrets.token_urlsafe(32)}"
            b1_key = self.generated_b1_bridge_key
        previous = self.initial or {}
        if activation_key:
            instance.set_activation_key(activation_key)
        elif bool(previous.get("activation_required")) != bool(instance.activation_required):
            instance.activation_revision = max(1, int(instance.activation_revision) + 1)
        if b1_key:
            instance.set_b1_key(b1_key)
        elif bool(previous.get("b1_enabled")) != bool(instance.b1_enabled):
            instance.b1_revision = max(1, int(instance.b1_revision) + 1)
        if commit:
            instance.save()
        return instance


@admin.register(DesktopSecurityConfiguration)
class DesktopSecurityConfigurationAdmin(admin.ModelAdmin):
    form = DesktopSecurityConfigurationForm
    fields = (
        "activation_required", "activation_key", "generate_activation_key", "activation_revision", "activation_key_hint",
        "b1_enabled", "b1_bridge_key", "generate_b1_bridge_key", "b1_revision", "b1_key_hint",
        "updated_by", "created_at", "updated_at",
    )
    readonly_fields = (
        "activation_revision", "activation_key_hint", "b1_revision", "b1_key_hint",
        "updated_by", "created_at", "updated_at",
    )
    list_display = (
        "activation_required", "activation_revision", "activation_key_hint",
        "b1_enabled", "b1_revision", "b1_key_hint", "updated_at", "updated_by",
    )
    actions = ("reveal_saved_keys",)

    def has_add_permission(self, request):
        return not DesktopSecurityConfiguration.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
        if form.generated_activation_key:
            self.message_user(
                request,
                f"Copy now — new OPTIX activation key: {form.generated_activation_key}",
                level=messages.WARNING,
            )
        if form.generated_b1_bridge_key:
            self.message_user(
                request,
                f"Copy now — new B1 bridge key: {form.generated_b1_bridge_key}",
                level=messages.WARNING,
            )

    @admin.action(description="Reveal saved OPTIX activation and B1 keys")
    def reveal_saved_keys(self, request, queryset):
        security = queryset.filter(pk=1).first()
        if security is None:
            self.message_user(request, "Select the global OPTIX desktop security record.", level=messages.ERROR)
            return
        try:
            activation_key = security.get_activation_key()
            b1_key = security.get_b1_key()
        except ValueError:
            self.message_user(request, "Saved key recovery failed. Check CONFIG_ENCRYPTION_SECRET.", level=messages.ERROR)
            return
        if not activation_key and not b1_key:
            self.message_user(request, "No saved keys exist yet.", level=messages.WARNING)
            return
        self.message_user(
            request,
            f"Saved activation key: {activation_key or 'Not set'} | Saved B1 bridge key: {b1_key or 'Not set'}",
            level=messages.WARNING,
        )


@admin.register(BootstrapAudit)
class BootstrapAuditAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "observed_ip",
        "reported_ip",
        "device_id",
        "client",
        "allowed",
        "reason",
        "app_version",
        "whitelist_link",
    )
    list_filter = ("allowed", "reason")
    search_fields = ("observed_ip", "reported_ip", "device_id", "client__name", "app_version")
    readonly_fields = (
        "created_at",
        "client",
        "observed_ip",
        "reported_ip",
        "device_id",
        "allowed",
        "reason",
        "app_version",
    )

    def get_urls(self):
        custom_urls = [
            path(
                "<int:audit_id>/whitelist/",
                self.admin_site.admin_view(self.whitelist_view),
                name="control_bootstrapaudit_whitelist",
            ),
        ]
        return custom_urls + super().get_urls()

    @admin.display(description="Access")
    def whitelist_link(self, obj):
        url = reverse("admin:control_bootstrapaudit_whitelist", args=(obj.pk,))
        if obj.client_id:
            label = "Open access"
            css = "button"
        else:
            label = "Whitelist"
            css = "button default"
        return format_html('<a class="{}" href="{}">{}</a>', css, url, label)

    def whitelist_view(self, request, audit_id):
        audit = get_object_or_404(BootstrapAudit, pk=audit_id)
        access_ip = (
            audit.reported_ip
            if settings.TRUST_APP_REPORTED_IPV4
            else audit.observed_ip
        )
        if not access_ip or not audit.device_id:
            self.message_user(
                request,
                "This audit does not contain the IP and device ID required for whitelisting.",
                level=messages.ERROR,
            )
            return redirect("admin:control_bootstrapaudit_changelist")

        existing = ClientAccess.objects.filter(
            device_id=audit.device_id,
        ).filter(
            Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        ).distinct().first()
        if existing:
            if not request.user.has_perm("control.change_clientaccess"):
                raise PermissionDenied
            if existing.active and existing.config_bundle.active:
                self.message_user(
                    request,
                    "This IP and device are already whitelisted.",
                    level=messages.INFO,
                )
            else:
                self.message_user(
                    request,
                    "An access record already exists. Activate it and confirm its configuration before saving.",
                    level=messages.WARNING,
                )
            return redirect("admin:control_clientaccess_change", existing.pk)

        if not request.user.has_perm("control.add_clientaccess"):
            raise PermissionDenied

        short_device_id = audit.device_id[:12]
        initial = {
            "name": f"Device {short_device_id}",
            "ipv4": access_ip,
            "device_id": audit.device_id,
            "active": "1",
            "profile_name": f"Device {short_device_id}",
            "notes": (
                f"Created from Bootstrap Audit #{audit.pk}. "
                f"Reason: {audit.reason or '-'}; app version: {audit.app_version or '-'}"
            ),
        }
        active_bundles = ConfigBundle.objects.filter(active=True)
        if active_bundles.count() == 1:
            initial["config_bundle"] = str(active_bundles.values_list("pk", flat=True).first())

        self.message_user(
            request,
            "Confirm the office, system number and configuration, then click Save to whitelist this device.",
            level=messages.INFO,
        )
        add_url = reverse("admin:control_clientaccess_add")
        return redirect(f"{add_url}?{urlencode(initial)}")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyGenerationJob)
class ProxyGenerationJobAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "provider_code", "country_code", "region", "city", "submitted_count", "requested_count", "candidate_count", "ready_count", "status", "created_at")
    list_filter = ("status", "provider_code", "country_code")
    search_fields = ("client__name", "client__office_name", "client__system_number")
    readonly_fields = ("client", "provider_code", "country_code", "region", "city", "submitted_count", "requested_count", "candidate_count", "ready_count", "status", "error", "created_at", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyInventoryAlert)
class ProxyInventoryAlertAdmin(admin.ModelAdmin):
    list_display = (
        "last_seen_at",
        "office_name",
        "system_number",
        "bundle_name",
        "provider_code",
        "country_code",
        "region",
        "availability",
        "occurrence_count",
        "status",
        "sent_at",
    )
    list_filter = (
        "status",
        "provider_code",
        "country_code",
        "office_name",
        "config_bundle",
    )
    search_fields = (
        "office_name",
        "system_number",
        "device_id",
        "config_bundle__name",
        "provider_message_id",
        "error",
    )
    readonly_fields = (
        "client",
        "dedupe_key",
        "config_bundle",
        "office_name",
        "system_number",
        "device_id",
        "provider_code",
        "country_code",
        "region",
        "city",
        "available_count",
        "requested_count",
        "occurrence_count",
        "status",
        "provider_message_id",
        "error",
        "first_seen_at",
        "last_seen_at",
        "sent_at",
    )

    @admin.display(description="Bundle")
    def bundle_name(self, obj):
        return obj.config_bundle.name if obj.config_bundle_id else "-"

    @admin.display(description="Ready / requested")
    def availability(self, obj):
        return f"{obj.available_count} / {obj.requested_count}"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(OfficeAuditRequest)
class OfficeAuditRequestAdmin(admin.ModelAdmin):
    """Manage request/command rows displayed by Office profile audit."""

    list_display = (
        "created_at",
        "office",
        "system_number",
        "device_name",
        "provider_code",
        "country_code",
        "submitted_count",
        "requested_count",
        "ready_count",
        "status",
        "error_preview",
    )
    list_filter = (
        ("created_at", admin.DateFieldListFilter),
        "client__office_name",
        "status",
        "provider_code",
        "country_code",
        "client__config_bundle",
    )
    search_fields = (
        "client__office_name",
        "client__name",
        "client__system_number",
        "client__ipv4",
        "client__device_id",
        "provider_code",
        "country_code",
        "region",
        "city",
        "error",
    )
    readonly_fields = (
        "client",
        "provider_code",
        "country_code",
        "region",
        "city",
        "submitted_count",
        "requested_count",
        "candidate_count",
        "ready_count",
        "status",
        "error",
        "created_at",
        "updated_at",
    )
    list_select_related = ("client", "client__config_bundle")
    list_per_page = 100
    preserve_filters = True

    @admin.display(description="Office", ordering="client__office_name")
    def office(self, obj):
        return obj.client.office_name or "Personal"

    @admin.display(description="System", ordering="client__system_number")
    def system_number(self, obj):
        return obj.client.system_number or "—"

    @admin.display(description="Device", ordering="client__name")
    def device_name(self, obj):
        return obj.client.name

    @admin.display(description="Error")
    def error_preview(self, obj):
        value = " ".join(str(obj.error or "").split())
        return value if len(value) <= 100 else f"{value[:97]}..."

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyReservation)
class ProxyReservationAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "job", "provider_code", "country_code", "region", "city", _profile_label, "profile_id", "reserved_at")
    list_filter = ("provider_code", "country_code")
    search_fields = ("client__name", "client__office_name", "profile_name", "profile_id", "proxy_fingerprint")
    readonly_fields = ("client", "job", "provider_code", "country_code", "region", "city", "proxy_fingerprint", "proxy_ciphertext", "profile_name", "profile_id", "reserved_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyExitIPCooldown)
class ProxyExitIPCooldownAdmin(admin.ModelAdmin):
    list_display = (
        "exit_ip",
        "provider_code",
        "client",
        "claimed_at",
        "available_after",
        "duplicate_attempts",
    )
    list_filter = ("provider_code", "claimed_at", "available_after")
    search_fields = (
        "exit_ip",
        "provider_code",
        "client__name",
        "client__office_name",
        "client__device_id",
    )
    readonly_fields = (
        "exit_ip",
        "provider_code",
        "client",
        "job",
        "reservation",
        "fraud_score",
        "claimed_at",
        "available_after",
        "duplicate_attempts",
        "last_duplicate_at",
        "created_at",
        "updated_at",
    )
    list_select_related = ("client", "job", "reservation")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ProfileActivity)
class ProfileActivityAdmin(admin.ModelAdmin):
    list_display = ("created_at", "client", "job", "reservation", "group_id", _profile_label, "profile_id", "status")
    list_filter = ("status", "group_id")
    search_fields = ("client__name", "client__office_name", "profile_name", "profile_id", "detail")
    readonly_fields = ("created_at", "client", "job", "reservation", "group_id", "profile_name", "profile_id", "status", "start_urls_json", "detail")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BrowserGroupMapping)
class BrowserGroupMappingAdmin(admin.ModelAdmin):
    list_display = ("internal_name", "browser_group_name", "browser_group_id", "client", "is_default", "active", "updated_at")
    list_filter = ("is_default", "active", "client__office_name")
    search_fields = ("internal_name", "browser_group_name", "browser_group_id", "client__ipv4", "client__device_id")
    list_editable = ("is_default", "active")


def _client_ip(obj):
    return obj.client.ipv4
_client_ip.short_description = "Client IP"


def _device_id(obj):
    return obj.client.device_id
_device_id.short_description = "Device ID"


ProfileActivityAdmin.list_display = ("created_at", _client_ip, _device_id, "client", "group_id", _profile_label, "profile_id", "status")
ProfileActivityAdmin.list_filter = ("status", "group_id", "client__office_name", "client__ipv4")
ProfileActivityAdmin.search_fields = ("client__ipv4", "client__device_id", "client__office_name", "profile_name", "profile_id", "start_urls_json", "detail")


@admin.register(OfficeProfileAudit)
class OfficeProfileAuditAdmin(admin.ModelAdmin):
    """Manage the lifecycle rows shown on the Office profile audit panel."""

    list_display = (
        "created_at",
        "office",
        "system_number",
        "device_name",
        "status",
        _profile_label,
        "profile_id",
        "group_id",
        "job_id",
        "detail_preview",
    )
    list_filter = (
        ("created_at", admin.DateFieldListFilter),
        "client__office_name",
        "status",
        "group_id",
        "client__config_bundle",
    )
    search_fields = (
        "client__office_name",
        "client__name",
        "client__system_number",
        "client__ipv4",
        "client__device_id",
        "profile_name",
        "profile_id",
        "group_id",
        "status",
        "start_urls_json",
        "detail",
    )
    readonly_fields = (
        "created_at",
        "client",
        "job",
        "reservation",
        "group_id",
        "profile_name",
        "profile_id",
        "status",
        "start_urls_json",
        "detail",
    )
    list_select_related = ("client", "client__config_bundle", "job", "reservation")
    list_per_page = 100
    preserve_filters = True

    @admin.display(description="Office", ordering="client__office_name")
    def office(self, obj):
        return obj.client.office_name or "Personal"

    @admin.display(description="System", ordering="client__system_number")
    def system_number(self, obj):
        return obj.client.system_number or "—"

    @admin.display(description="Device", ordering="client__name")
    def device_name(self, obj):
        return obj.client.name

    @admin.display(description="Detail")
    def detail_preview(self, obj):
        value = " ".join(str(obj.detail or "").split())
        return value if len(value) <= 100 else f"{value[:97]}..."

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProfileDomainActivity)
class ProfileDomainActivityAdmin(admin.ModelAdmin):
    list_display = (
        "last_visited_at",
        "domain",
        _client_ip,
        _device_id,
        "client",
        "group_id",
        _profile_label,
        "profile_id",
        "visit_count",
    )
    list_filter = (
        ("last_visited_at", admin.DateFieldListFilter),
        "group_id",
        "client__office_name",
        "client__ipv4",
    )
    search_fields = (
        "domain",
        "client__ipv4",
        "client__device_id",
        "client__office_name",
        "profile_name",
        "profile_id",
        "browser_id",
        "session_id",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
        "client",
        "job",
        "reservation",
        "session_id",
        "group_id",
        "profile_name",
        "profile_id",
        "browser_id",
        "domain",
        "first_visited_at",
        "last_visited_at",
        "visit_count",
        "session_started_at",
        "session_ended_at",
    )
    list_select_related = ("client", "job", "reservation")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(OfficeAuditDomain)
class OfficeAuditDomainAdmin(admin.ModelAdmin):
    """Manage domain rows displayed by Office profile audit."""

    list_display = (
        "last_visited_at",
        "office",
        "system_number",
        "device_name",
        "domain",
        _profile_label,
        "profile_id",
        "group_id",
        "visit_count",
    )
    list_filter = (
        ("last_visited_at", admin.DateFieldListFilter),
        "client__office_name",
        "group_id",
        "client__config_bundle",
    )
    search_fields = (
        "client__office_name",
        "client__name",
        "client__system_number",
        "client__ipv4",
        "client__device_id",
        "domain",
        "profile_name",
        "profile_id",
        "browser_id",
        "session_id",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
        "client",
        "job",
        "reservation",
        "session_id",
        "group_id",
        "profile_name",
        "profile_id",
        "browser_id",
        "domain",
        "first_visited_at",
        "last_visited_at",
        "visit_count",
        "session_started_at",
        "session_ended_at",
    )
    list_select_related = ("client", "client__config_bundle", "job", "reservation")
    list_per_page = 100
    preserve_filters = True

    @admin.display(description="Office", ordering="client__office_name")
    def office(self, obj):
        return obj.client.office_name or "Personal"

    @admin.display(description="System", ordering="client__system_number")
    def system_number(self, obj):
        return obj.client.system_number or "—"

    @admin.display(description="Device", ordering="client__name")
    def device_name(self, obj):
        return obj.client.name

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyPoolTarget)
class ProxyPoolTargetAdmin(admin.ModelAdmin):
    change_list_template = "admin/control/proxypooltarget/change_list.html"
    list_display = ("provider_code", "country_code", "region", "city", "config_bundle", "target_count", "replenish_below", "active", "available_entries", "generate_link")
    list_filter = ("provider_code", "country_code", "active")
    search_fields = ("provider_code", "country_code", "region", "city", "config_bundle__name")
    list_select_related = ("config_bundle",)

    def get_urls(self):
        custom = [path("generate/", self.admin_site.admin_view(self.generate_view), name="control_proxypooltarget_generate")]
        return custom + super().get_urls()

    @admin.display(description="Available")
    def available_entries(self, obj):
        return obj.entries.filter(state="available").count()

    @admin.display(description="Generate")
    def generate_link(self, obj):
        return format_html('<a class="button" href="{}">Generate countries</a>', reverse("admin:control_proxypooltarget_generate"))

    def generate_view(self, request: HttpRequest) -> HttpResponse:
        form = ProxyPoolGenerateForm(request.POST or None)
        if request.method == "POST" and form.is_valid():
            providers = list(form.cleaned_data["provider_codes"])
            countries = form.cleaned_data["country_codes"]
            bundle = form.cleaned_data["config_bundle"]
            target_count = form.cleaned_data["target_count"]
            replenish_below = form.cleaned_data["replenish_below"]
            targets = []
            with transaction.atomic():
                if form.cleaned_data["purge_existing"]:
                    ProxyPoolEntry.objects.filter(target__config_bundle=bundle, target__provider_code__in=providers, target__country_code__in=countries).delete()
                for provider_code in providers:
                    for country_code in countries:
                        target, _ = ProxyPoolTarget.objects.get_or_create(
                            config_bundle=bundle, provider_code=provider_code, country_code=country_code, region="", city="",
                            defaults={"target_count": target_count, "replenish_below": replenish_below, "active": True},
                        )
                        target.target_count = target_count
                        target.replenish_below = replenish_below
                        target.active = True
                        target.save(update_fields=("target_count", "replenish_below", "active"))
                        targets.append(target)
            queued = sum(1 for target in targets if queue_refill_proxy_pool(target.pk))
            messages.success(request, f"Prepared {len(targets)} pool target(s); queued {queued} refill job(s). The Celery worker will generate them asynchronously.")
            return redirect("admin:control_proxypooltarget_changelist")
        return TemplateResponse(request, "admin/control/proxypooltarget/generate.html", {**self.admin_site.each_context(request), "title": "Generate proxy pools by country", "form": form})
@admin.register(ProxyPoolEntry)
class ProxyPoolEntryAdmin(admin.ModelAdmin):
    list_display = ("target", "state", "exit_ip", "fraud_score", "reserved_client", "created_at", "reserved_at")
    list_filter = ("state", "target__provider_code", "target__country_code")
    search_fields = ("proxy_fingerprint", "exit_ip", "reserved_client__device_id")
    readonly_fields = ("proxy_fingerprint", "proxy_ciphertext", "created_at", "tested_at", "reserved_at")
    list_select_related = ("target", "reserved_client")
@admin.register(MonitoredDomain)
class MonitoredDomainAdmin(admin.ModelAdmin):
    list_display = ("domain", "label", "active", "created_by", "created_at", "updated_at")
    list_filter = ("active",)
    search_fields = ("domain", "label")
    list_editable = ("active",)
    readonly_fields = ("created_by", "created_at", "updated_at")

    def save_model(self, request, obj, form, change):
        if not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(YSBridgeAgent)
class YSBridgeAgentAdmin(admin.ModelAdmin):
    list_display = ("name", "active", "version", "last_ip", "last_seen_at", "updated_at")
    list_filter = ("active",)
    search_fields = ("name", "last_ip", "token_hint")
    readonly_fields = (
        "token_hash",
        "token_hint",
        "version",
        "last_ip",
        "last_seen_at",
        "created_at",
        "updated_at",
    )


@admin.register(YSBridgeCommand)
class YSBridgeCommandAdmin(admin.ModelAdmin):
    list_display = ("action", "office_name", "agent", "status", "requested_by", "requested_at", "completed_at")
    list_filter = ("status", "action", "agent")
    search_fields = ("office_name", "id", "error", "requested_by__username")
    readonly_fields = (
        "id",
        "agent",
        "action",
        "office_name",
        "payload",
        "status",
        "requested_by",
        "result",
        "error",
        "requested_at",
        "claimed_at",
        "completed_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
