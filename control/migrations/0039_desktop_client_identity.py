from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0038_operations_panel_controls")]

    operations = [
        migrations.AddField(model_name="clientaccess", name="desktop_activation_revision", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="clientaccess", name="desktop_client_detected_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(
            model_name="clientaccess",
            name="desktop_client_product",
            field=models.CharField(
                blank=True,
                choices=[("", "Not detected"), ("legacy", "I am the best"), ("dollar", "Dollar")],
                default="",
                help_text="Last desktop product positively identified during bootstrap.",
                max_length=16,
            ),
        ),
        migrations.AddField(model_name="clientaccess", name="desktop_client_version", field=models.CharField(blank=True, default="", max_length=40)),
    ]
