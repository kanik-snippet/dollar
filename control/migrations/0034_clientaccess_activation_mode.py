from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("control", "0033_desktop_security_activation_recovery"),
    ]

    operations = [
        migrations.AddField(
            model_name="clientaccess",
            name="activation_mode",
            field=models.CharField(
                choices=[
                    ("inherit", "Inherit global OPTIX activation setting"),
                    ("require", "Require OPTIX activation for this PC"),
                    ("bypass", "Legacy bypass — do not require OPTIX activation"),
                ],
                default="inherit",
                help_text="Override the global OPTIX activation requirement for this individual PC.",
                max_length=16,
            ),
        ),
    ]
