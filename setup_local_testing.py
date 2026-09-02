from __future__ import annotations

import json
import os
from pathlib import Path

import django


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("LOCAL_TESTING_CONFIG", ROOT / "local_testing_config.json"))
PROXY_ROOT = Path(os.getenv("LOCAL_PROXY_ROOT", ROOT / "local_proxy"))


def main() -> None:
    if not CONFIG_PATH.is_file():
        example = ROOT / "local_testing_config.example.json"
        raise SystemExit(
            f"Create {CONFIG_PATH.name} from {example.name} and fill the local YS API key first."
        )
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("config"), dict):
        raise SystemExit("local_testing_config.json must contain an object with a config object.")

    django.setup()
    from control.models import ClientAccess, ConfigBundle, Provider, ProxyCountryFile

    bundle, _ = ConfigBundle.objects.update_or_create(
        name=str(payload.get("bundle_name") or "LOCAL-TESTING"),
        defaults={
            "active": True,
            "browser_group_id": str(payload.get("browser_group_id") or ""),
            "browser_group_name": str(payload.get("browser_group_name") or "Local Testing"),
        },
    )
    bundle.set_payload({str(k): str(v) for k, v in payload["config"].items()})
    bundle.save(update_fields=("payload_ciphertext", "updated_at"))

    ClientAccess.objects.update_or_create(
        name="Local test device",
        defaults={
            "ipv4": "127.0.0.1",
            "device_id": "",
            "active": True,
            "office_name": str(payload.get("office_name") or "LOCAL"),
            "system_number": str(payload.get("system_number") or "local-1"),
            "profile_name": str(payload.get("profile_name") or "Local Test Device"),
            "config_bundle": bundle,
        },
    )

    imported = 0
    for file_path in sorted(PROXY_ROOT.glob("*/*.txt")):
        provider_code = file_path.parent.name.strip().upper()
        country_code = file_path.stem.strip().upper()
        if not provider_code or not country_code:
            continue
        provider, _ = Provider.objects.update_or_create(
            code=provider_code,
            defaults={"display_name": provider_code, "active": True},
        )
        item, _ = ProxyCountryFile.objects.update_or_create(
            provider=provider,
            country_code=country_code,
            defaults={
                "country_name": country_code,
                "version": 1,
                "active": True,
            },
        )
        item.set_content(file_path.read_text(encoding="utf-8"))
        item.save(update_fields=("content_ciphertext", "content_sha256", "updated_at"))
        imported += 1
    print(f"Local testing database ready: bundle={bundle.name}, proxy files imported={imported}")


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "controlserver.settings")
    main()
