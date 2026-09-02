from django.db import migrations, models
from django.db.models import F


def copy_requested_count(apps, schema_editor):
    ProxyGenerationJob = apps.get_model("control", "ProxyGenerationJob")
    ProxyGenerationJob.objects.update(candidate_count=F("requested_count"))


class Migration(migrations.Migration):
    dependencies = [("control", "0020_proxypoolentry_target_state_idx")]

    operations = [
        migrations.AddField(
            model_name="proxygenerationjob",
            name="candidate_count",
            field=models.PositiveSmallIntegerField(
                default=1,
                help_text=(
                    "Maximum proxy candidates reserved for quality testing; "
                    "profile counts continue to use requested_count."
                ),
            ),
        ),
        migrations.RunPython(copy_requested_count, migrations.RunPython.noop),
    ]
