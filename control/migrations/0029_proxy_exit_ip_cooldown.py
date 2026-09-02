import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("control", "0028_proxycitycatalog"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProxyExitIPCooldown",
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
                ("exit_ip", models.GenericIPAddressField(unique=True)),
                ("provider_code", models.CharField(blank=True, max_length=32)),
                ("fraud_score", models.IntegerField(blank=True, null=True)),
                ("claimed_at", models.DateTimeField()),
                ("available_after", models.DateTimeField(db_index=True)),
                ("duplicate_attempts", models.PositiveIntegerField(default=0)),
                ("last_duplicate_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "client",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="proxy_exit_ip_cooldowns",
                        to="control.clientaccess",
                    ),
                ),
                (
                    "job",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="exit_ip_cooldowns",
                        to="control.proxygenerationjob",
                    ),
                ),
                (
                    "reservation",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="exit_ip_cooldowns",
                        to="control.proxyreservation",
                    ),
                ),
            ],
            options={
                "verbose_name": "Proxy exit-IP cooldown",
                "verbose_name_plural": "Proxy exit-IP cooldowns",
                "ordering": ("-claimed_at", "exit_ip"),
            },
        ),
    ]
