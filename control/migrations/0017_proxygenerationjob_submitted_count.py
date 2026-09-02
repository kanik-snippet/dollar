from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0016_clientaccessip"),
    ]

    operations = [
        migrations.AddField(
            model_name="proxygenerationjob",
            name="submitted_count",
            field=models.PositiveSmallIntegerField(
                default=1,
                help_text="Number requested by the client before the server safety cap.",
            ),
        ),
        migrations.RunPython(
            lambda apps, schema_editor: apps.get_model("control", "ProxyGenerationJob")
            .objects.update(submitted_count=models.F("requested_count")),
            migrations.RunPython.noop,
        ),
    ]
