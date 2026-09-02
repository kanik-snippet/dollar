import control.models
import control.storage
import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("control", "0026_ysbridgeagent_ysbridgecommand"),
    ]

    operations = [
        migrations.AddField(
            model_name="clientaccess",
            name="release_channel",
            field=models.CharField(
                choices=[("public", "Public"), ("testing", "Testing")],
                default="public",
                help_text="Desktop release channel assigned by an administrator.",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="DesktopRelease",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "channel",
                    models.CharField(
                        choices=[("public", "Public"), ("testing", "Testing")],
                        default="public",
                        max_length=16,
                    ),
                ),
                (
                    "version",
                    models.CharField(
                        help_text="Numeric dotted version, for example 1.7.35.",
                        max_length=40,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Use a numeric dotted version such as 1.7.35.",
                                regex="\\A[0-9]+(?:\\.[0-9]+){2,3}\\Z",
                            )
                        ],
                    ),
                ),
                (
                    "build_number",
                    models.PositiveBigIntegerField(
                        help_text="Monotonically increasing build number within this channel.",
                        validators=[django.core.validators.MinValueValidator(1)],
                    ),
                ),
                (
                    "mode",
                    models.CharField(
                        choices=[
                            ("optional", "Optional"),
                            ("silent", "Silent automatic install"),
                            ("mandatory", "Mandatory automatic install"),
                        ],
                        default="optional",
                        max_length=16,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("published", "Published"),
                            ("revoked", "Revoked"),
                        ],
                        default="draft",
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "target_offices",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Office names allowed to receive this release; [] targets all offices.",
                    ),
                ),
                (
                    "target_device_ids",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Device IDs allowed to receive this release; [] targets all devices.",
                    ),
                ),
                (
                    "artifact",
                    models.FileField(
                        storage=control.storage.PrivateDesktopReleaseStorage(),
                        upload_to=control.models.desktop_release_artifact_path,
                        validators=[
                            django.core.validators.FileExtensionValidator(
                                allowed_extensions=("exe",)
                            )
                        ],
                    ),
                ),
                (
                    "original_filename",
                    models.CharField(
                        blank=True,
                        editable=False,
                        max_length=255,
                    ),
                ),
                (
                    "artifact_sha256",
                    models.CharField(
                        blank=True,
                        editable=False,
                        max_length=64,
                    ),
                ),
                (
                    "artifact_size",
                    models.PositiveBigIntegerField(default=0, editable=False),
                ),
                (
                    "signature_b64",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Detached Ed25519 signature of the canonical manifest payload.",
                    ),
                ),
                (
                    "published_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="desktop_releases",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-build_number", "-pk"),
                "indexes": [
                    models.Index(
                        fields=["channel", "status", "-build_number"],
                        name="release_lookup_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("channel", "build_number"),
                        name="unique_desktop_release_build",
                    )
                ],
            },
        ),
    ]
