import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0009_config_group_device_profile")]

    operations = [
        migrations.CreateModel(
            name="ProxyRegionCatalog",
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
                    "country_code",
                    models.CharField(
                        max_length=32,
                        validators=[
                            django.core.validators.RegexValidator(
                                message=(
                                    "Use only letters, numbers, underscores, and hyphens."
                                ),
                                regex="^[A-Za-z0-9_-]{1,32}$",
                            )
                        ],
                    ),
                ),
                ("region_code", models.CharField(max_length=120)),
                ("region_name", models.CharField(max_length=160)),
                ("source", models.CharField(blank=True, default="", max_length=40)),
                ("active", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="region_catalog",
                        to="control.provider",
                    ),
                ),
            ],
            options={
                "ordering": (
                    "provider__display_order",
                    "country_code",
                    "region_name",
                )
            },
        ),
        migrations.AddConstraint(
            model_name="proxyregioncatalog",
            constraint=models.UniqueConstraint(
                fields=("provider", "country_code", "region_code"),
                name="unique_provider_country_region",
            ),
        ),
    ]
