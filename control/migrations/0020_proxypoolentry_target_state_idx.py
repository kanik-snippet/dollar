from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0019_profilecreatequeue"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="proxypoolentry",
            index=models.Index(
                fields=("target", "state"),
                name="poolentry_target_state_idx",
            ),
        ),
    ]
