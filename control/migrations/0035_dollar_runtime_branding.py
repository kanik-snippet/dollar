from django.db import migrations


def brand_runtime_as_dollar(apps, schema_editor):
    RuntimeConfig = apps.get_model("control", "DesktopRuntimeConfiguration")
    for runtime in RuntimeConfig.objects.all().iterator():
        ui = dict(runtime.ui_config or {})
        ui["appName"] = "Dollar"
        browsers = []
        for browser in ui.get("browsers") or []:
            item = dict(browser)
            if str(item.get("id") or "").upper() == "B1":
                item["name"] = "B1 - Dollar Electron"
            browsers.append(item)
        if browsers:
            ui["browsers"] = browsers
        runtime.ui_config = ui
        runtime.save(update_fields=["ui_config", "updated_at"])


class Migration(migrations.Migration):
    dependencies = [("control", "0034_clientaccess_activation_mode")]
    operations = [migrations.RunPython(brand_runtime_as_dollar, migrations.RunPython.noop)]
