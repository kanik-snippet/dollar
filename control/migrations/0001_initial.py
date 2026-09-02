from django.db import migrations, models
import django.db.models.deletion
import django.core.validators


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ConfigBundle",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("active", models.BooleanField(default=True)),
                ("payload_ciphertext", models.TextField(blank=True, editable=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="Provider",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(max_length=32, unique=True, validators=[django.core.validators.RegexValidator(message="Use only letters, numbers, underscores, and hyphens.", regex="^[A-Za-z0-9_-]{1,32}$")])),
                ("display_name", models.CharField(max_length=64)),
                ("display_order", models.PositiveIntegerField(default=0)),
                ("active", models.BooleanField(default=True)),
            ],
            options={"ordering": ("display_order", "code")},
        ),
        migrations.CreateModel(
            name="ClientAccess",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120)),
                ("ipv4", models.GenericIPAddressField(protocol="IPv4")),
                ("device_id", models.CharField(blank=True, default="", help_text="Stable desktop identifier; leave blank for IP-only access.", max_length=128)),
                ("active", models.BooleanField(default=True)),
                ("office_name", models.CharField(max_length=64)),
                ("system_number", models.CharField(max_length=32)),
                ("notes", models.TextField(blank=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("config_bundle", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="clients", to="control.configbundle")),
            ],
            options={"verbose_name_plural": "Client access entries", "ordering": ("office_name", "system_number", "name")},
        ),
        migrations.CreateModel(
            name="ProxyCountryFile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("country_code", models.CharField(max_length=32, validators=[django.core.validators.RegexValidator(message="Use only letters, numbers, underscores, and hyphens.", regex="^[A-Za-z0-9_-]{1,32}$")])),
                ("country_name", models.CharField(max_length=80)),
                ("version", models.PositiveIntegerField(default=1)),
                ("active", models.BooleanField(default=True)),
                ("content_ciphertext", models.TextField(blank=True, editable=False)),
                ("content_sha256", models.CharField(blank=True, editable=False, max_length=64)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("provider", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="country_files", to="control.provider")),
            ],
            options={"ordering": ("provider__display_order", "country_name")},
        ),
        migrations.CreateModel(
            name="BootstrapAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("observed_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("reported_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("device_id", models.CharField(blank=True, max_length=128)),
                ("allowed", models.BooleanField(default=False)),
                ("reason", models.CharField(max_length=80)),
                ("app_version", models.CharField(blank=True, max_length=40)),
                ("client", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="audit_events", to="control.clientaccess")),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddConstraint(
            model_name="clientaccess",
            constraint=models.UniqueConstraint(fields=("ipv4", "device_id"), name="unique_ipv4_device_access"),
        ),
        migrations.AddConstraint(
            model_name="proxycountryfile",
            constraint=models.UniqueConstraint(fields=("provider", "country_code"), name="unique_provider_country_file"),
        ),
    ]
