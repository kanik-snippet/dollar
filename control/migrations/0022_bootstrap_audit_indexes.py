from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0021_proxygenerationjob_candidate_count"),
    ]

    operations = [
        migrations.AlterField(
            model_name="bootstrapaudit",
            name="created_at",
            field=models.DateTimeField(auto_now_add=True, db_index=True),
        ),
        migrations.AlterField(
            model_name="bootstrapaudit",
            name="device_id",
            field=models.CharField(blank=True, db_index=True, max_length=128),
        ),
        migrations.AlterField(
            model_name="bootstrapaudit",
            name="observed_ip",
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name="bootstrapaudit",
            name="reported_ip",
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AddIndex(
            model_name="bootstrapaudit",
            index=models.Index(
                fields=["allowed", "-id"],
                name="audit_allowed_id_idx",
            ),
        ),
    ]
