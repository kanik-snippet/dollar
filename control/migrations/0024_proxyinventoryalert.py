import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0023_officeprofileaudit"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProxyInventoryAlert",
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
                    "dedupe_key",
                    models.CharField(editable=False, max_length=64, unique=True),
                ),
                ("office_name", models.CharField(blank=True, max_length=160)),
                ("system_number", models.CharField(blank=True, max_length=80)),
                ("device_id", models.CharField(blank=True, max_length=128)),
                ("provider_code", models.CharField(max_length=32)),
                ("country_code", models.CharField(max_length=32)),
                ("region", models.CharField(blank=True, max_length=120)),
                ("city", models.CharField(blank=True, max_length=120)),
                ("available_count", models.PositiveSmallIntegerField(default=0)),
                ("requested_count", models.PositiveSmallIntegerField(default=1)),
                ("occurrence_count", models.PositiveIntegerField(default=1)),
                ("status", models.CharField(default="pending", max_length=24)),
                ("provider_message_id", models.CharField(blank=True, max_length=80)),
                ("error", models.TextField(blank=True)),
                ("first_seen_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen_at", models.DateTimeField(auto_now=True)),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
                (
                    "client",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="proxy_inventory_alerts",
                        to="control.clientaccess",
                    ),
                ),
                (
                    "config_bundle",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="proxy_inventory_alerts",
                        to="control.configbundle",
                    ),
                ),
            ],
            options={
                "ordering": ("-last_seen_at", "-pk"),
                "indexes": [
                    models.Index(
                        fields=[
                            "config_bundle",
                            "provider_code",
                            "country_code",
                            "region",
                            "city",
                        ],
                        name="proxy_alert_scope_idx",
                    ),
                    models.Index(
                        fields=["status", "last_seen_at"],
                        name="proxy_alert_status_idx",
                    ),
                ],
            },
        ),
    ]
