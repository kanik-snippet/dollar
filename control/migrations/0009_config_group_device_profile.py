from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0008_profile_domain_activity"),
    ]

    operations = [
        migrations.AddField(
            model_name="configbundle",
            name="browser_group_id",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Numeric browser group ID assigned to every device using this bundle.",
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name="configbundle",
            name="browser_group_name",
            field=models.CharField(
                default="Testing",
                help_text="Browser group name used for display and as a fallback when no ID is set.",
                max_length=160,
            ),
        ),
        migrations.AddField(
            model_name="clientaccess",
            name="profile_name",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Fixed browser profile name for this device. Defaults to the access-record name.",
                max_length=160,
            ),
        ),
    ]
