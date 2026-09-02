from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("control", "0011_proxypooltarget_refill_pending"),
    ]

    operations = [
        migrations.CreateModel(
            name="MonitoredDomain",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("domain", models.CharField(max_length=253, unique=True)),
                ("label", models.CharField(max_length=120, blank=True, default="")),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="monitored_domains", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ("domain",),
                "verbose_name": "Monitored domain",
                "verbose_name_plural": "Monitored domains",
            },
        ),
    ]
