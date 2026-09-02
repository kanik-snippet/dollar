from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0001_initial")]
    operations = [migrations.CreateModel(name="ExtensionPackage", fields=[
        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
        ("name", models.CharField(max_length=120, unique=True)),
        ("filename", models.CharField(max_length=180)),
        ("version", models.PositiveIntegerField(default=1)),
        ("active", models.BooleanField(default=True)),
        ("is_top", models.BooleanField(default=False)),
        ("status", models.BooleanField(default=True)),
        ("package_ciphertext", models.TextField(blank=True, editable=False)),
        ("package_sha256", models.CharField(blank=True, editable=False, max_length=64)),
        ("updated_at", models.DateTimeField(auto_now=True)),
    ], options={"ordering": ("name",)})]
