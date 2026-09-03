from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def mark_existing_audits_read(apps, schema_editor):
    BootstrapAudit = apps.get_model("control", "BootstrapAudit")
    BootstrapAudit.objects.filter(read_at__isnull=True).update(read_at=models.F("created_at"))


class Migration(migrations.Migration):

    dependencies = [
        ("control", "0037_desktopofficeaccesspolicy_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(model_name="clientaccess", name="desktop_remote_action", field=models.CharField(blank=True, choices=[("", "No remote action"), ("uninstall", "Uninstall Dollar")], default="", help_text="Pending command delivered to this authorized Dollar installation.", max_length=24)),
        migrations.AddField(model_name="clientaccess", name="desktop_remote_action_acknowledged_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="clientaccess", name="desktop_remote_action_requested_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="clientaccess", name="desktop_remote_action_requested_by", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="requested_desktop_remote_actions", to=settings.AUTH_USER_MODEL)),
        migrations.AddField(model_name="clientaccess", name="desktop_remote_action_revision", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="bootstrapaudit", name="read_at", field=models.DateTimeField(blank=True, db_index=True, null=True)),
        migrations.AddField(model_name="bootstrapaudit", name="review_status", field=models.CharField(choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")], db_index=True, default="pending", max_length=16)),
        migrations.AddField(model_name="bootstrapaudit", name="reviewed_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="bootstrapaudit", name="reviewed_by", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="reviewed_bootstrap_audits", to=settings.AUTH_USER_MODEL)),
        migrations.AddIndex(model_name="bootstrapaudit", index=models.Index(fields=["allowed", "review_status", "-id"], name="audit_review_status_idx")),
        migrations.RunPython(mark_existing_audits_read, migrations.RunPython.noop),
    ]
