from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0040_backfill_desktop_client_identity")]
    operations = [migrations.CreateModel(
        name="BrowserCatalogSnapshot",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("name", models.CharField(max_length=32, unique=True)),
            ("payload", models.JSONField(default=dict)),
            ("revision", models.CharField(blank=True, default="", max_length=64)),
            ("last_attempt_at", models.DateTimeField(blank=True, null=True)),
            ("last_success_at", models.DateTimeField(blank=True, null=True)),
            ("data_updated_at", models.DateTimeField(blank=True, null=True)),
            ("last_error", models.CharField(blank=True, default="", max_length=300)),
            ("lease_token", models.CharField(blank=True, default="", max_length=32)),
            ("lease_until", models.DateTimeField(blank=True, null=True)),
        ],
        options={"verbose_name": "YS browser catalog sync", "verbose_name_plural": "YS browser catalog sync status"},
    )]
