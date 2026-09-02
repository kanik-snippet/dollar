from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("control", "0031_desktop_runtime_configuration"),
    ]

    operations = [
        migrations.CreateModel(
            name="DesktopSecurityConfiguration",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("activation_required", models.BooleanField(default=False, help_text="When enabled, every OPTIX installation must present the current activation key.")),
                ("activation_key_hash", models.CharField(blank=True, editable=False, max_length=256)),
                ("activation_key_hint", models.CharField(blank=True, editable=False, max_length=16)),
                ("activation_revision", models.PositiveBigIntegerField(default=1, validators=[django.core.validators.MinValueValidator(1)])),
                ("b1_enabled", models.BooleanField(default=False, help_text="Allow B1 (the local OPTIX Electron bridge) for activated clients.")),
                ("b1_key_ciphertext", models.TextField(blank=True, editable=False)),
                ("b1_key_hint", models.CharField(blank=True, editable=False, max_length=16)),
                ("b1_revision", models.PositiveBigIntegerField(default=1, validators=[django.core.validators.MinValueValidator(1)])),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="desktop_security_configurations", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "OPTIX desktop security",
                "verbose_name_plural": "OPTIX desktop security",
            },
        ),
    ]
