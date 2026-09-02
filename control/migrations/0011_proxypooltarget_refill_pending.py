from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("control", "0010_proxyregioncatalog"),
    ]

    operations = [
        migrations.AddField(
            model_name="proxypooltarget",
            name="refill_pending",
            field=models.BooleanField(
                default=False,
                editable=False,
            ),
        ),
    ]
