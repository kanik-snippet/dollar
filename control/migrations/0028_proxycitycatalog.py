from django.db import migrations, models
import django.core.validators
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0027_desktoprelease_clientaccess_release_channel"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProxyCityCatalog",
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
                ("account_key", models.CharField(max_length=64)),
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
                ("region_code", models.CharField(blank=True, max_length=120)),
                ("city_name", models.CharField(max_length=120)),
                ("source", models.CharField(blank=True, default="", max_length=40)),
                ("active", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="city_catalog",
                        to="control.provider",
                    ),
                ),
            ],
            options={
                "ordering": (
                    "provider__display_order",
                    "account_key",
                    "country_code",
                    "region_code",
                    "city_name",
                ),
            },
        ),
        migrations.AddConstraint(
            model_name="proxycitycatalog",
            constraint=models.UniqueConstraint(
                fields=(
                    "provider",
                    "account_key",
                    "country_code",
                    "region_code",
                    "city_name",
                ),
                name="unique_p2_account_country_region_city",
            ),
        ),
        migrations.AddIndex(
            model_name="proxycitycatalog",
            index=models.Index(
                fields=[
                    "provider",
                    "account_key",
                    "country_code",
                    "region_code",
                    "active",
                ],
                name="proxycity_account_scope_idx",
            ),
        ),
    ]
