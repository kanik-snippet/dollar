import re

from django.db import migrations


def backfill_identity(apps, schema_editor):
    ClientAccess = apps.get_model("control", "ClientAccess")
    BootstrapAudit = apps.get_model("control", "BootstrapAudit")
    for client in ClientAccess.objects.filter(desktop_client_product="").iterator(chunk_size=100):
        audit = BootstrapAudit.objects.filter(client_id=client.pk).exclude(app_version="").order_by("-id").only("app_version", "created_at").first()
        if audit is None:
            continue
        parts = [int(value) for value in re.findall(r"\d+", audit.app_version)[:2]]
        product = "legacy" if parts and tuple(parts) >= (1, 7) else "dollar"
        ClientAccess.objects.filter(pk=client.pk).update(
            desktop_client_product=product,
            desktop_client_version=audit.app_version[:40],
            desktop_client_detected_at=audit.created_at,
        )


class Migration(migrations.Migration):
    dependencies = [("control", "0039_desktop_client_identity")]
    operations = [migrations.RunPython(backfill_identity, migrations.RunPython.noop)]
