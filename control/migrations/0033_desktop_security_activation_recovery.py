from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("control", "0032_desktop_security_configuration"),
    ]

    operations = [
        migrations.AddField(
            model_name="desktopsecurityconfiguration",
            name="activation_key_ciphertext",
            field=models.TextField(blank=True, editable=False),
        ),
    ]
