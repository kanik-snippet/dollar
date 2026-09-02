from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0024_proxyinventoryalert")]

    operations = [
        migrations.AddField(
            model_name="proxypooltarget",
            name="refill_requested_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
    ]
