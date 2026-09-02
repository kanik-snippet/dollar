import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("control", "0025_proxypooltarget_refill_requested_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="YSBridgeAgent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True)),
                ("token_hash", models.CharField(editable=False, max_length=64, unique=True)),
                ("token_hint", models.CharField(blank=True, editable=False, max_length=16)),
                ("active", models.BooleanField(default=True)),
                ("version", models.CharField(blank=True, default="", max_length=40)),
                ("last_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="YSBridgeCommand",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("action", models.CharField(choices=[("delete_environments", "Delete YSBrowser environments"), ("whitelist_add", "Add YSBrowser whitelist IP"), ("whitelist_remove", "Remove YSBrowser whitelist IP")], max_length=40)),
                ("office_name", models.CharField(blank=True, default="", max_length=160)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed"), ("cancelled", "Cancelled")], default="queued", max_length=20)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True, default="")),
                ("requested_at", models.DateTimeField(auto_now_add=True)),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("agent", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="commands", to="control.ysbridgeagent")),
                ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="ys_bridge_commands", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ("-requested_at",),
                "indexes": [models.Index(fields=["agent", "status", "requested_at"], name="ysbridge_claim_idx")],
            },
        ),
    ]
