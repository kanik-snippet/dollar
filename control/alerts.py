from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings

from .models import ProxyInventoryAlert


class AlertConfigurationError(RuntimeError):
    pass


# Backward-compatible import for any older queued worker code.
SMSConfigurationError = AlertConfigurationError


def alert_message(alert: ProxyInventoryAlert) -> str:
    location = alert.country_code
    if alert.region:
        location += f"/{alert.region}"
    bundle = alert.config_bundle.name if alert.config_bundle_id else "unassigned"
    device = alert.system_number or (alert.device_id[:12] if alert.device_id else "unknown")
    return (
        "PROXY INVENTORY ALERT | "
        f"Office: {alert.office_name or '-'} | "
        f"Device: {device} | Bundle: {bundle} | "
        f"{alert.provider_code} {location} | "
        f"Ready: {alert.available_count}/{alert.requested_count}"
    )


def _twilio_recipients() -> list[str]:
    return [
        value.strip()
        for value in str(settings.PROXY_ALERT_SMS_TO or "").split(",")
        if value.strip()
    ]


def send_twilio_proxy_alert(alert: ProxyInventoryAlert) -> list[str]:
    """Send one normal SMS to every configured E.164 recipient."""
    account_sid = str(settings.TWILIO_ACCOUNT_SID or "").strip()
    auth_token = str(settings.TWILIO_AUTH_TOKEN or "").strip()
    from_number = str(settings.TWILIO_FROM_NUMBER or "").strip()
    messaging_service = str(settings.TWILIO_MESSAGING_SERVICE_SID or "").strip()
    recipients = _twilio_recipients()
    if not account_sid or not auth_token or not recipients:
        raise AlertConfigurationError(
            "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and PROXY_ALERT_SMS_TO are required."
        )
    if not from_number and not messaging_service:
        raise AlertConfigurationError(
            "Set TWILIO_FROM_NUMBER or TWILIO_MESSAGING_SERVICE_SID."
        )

    endpoint = (
        "https://api.twilio.com/2010-04-01/Accounts/"
        f"{urllib.parse.quote(account_sid, safe='')}/Messages.json"
    )
    authorization = base64.b64encode(
        f"{account_sid}:{auth_token}".encode("utf-8")
    ).decode("ascii")
    message_ids: list[str] = []
    body = alert_message(alert)

    for recipient in recipients:
        form = {"To": recipient, "Body": body}
        if messaging_service:
            form["MessagingServiceSid"] = messaging_service
        else:
            form["From"] = from_number
        request = urllib.request.Request(
            endpoint,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=settings.PROXY_ALERT_TIMEOUT_SECONDS,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Twilio HTTP {exc.code}: {detail}") from exc
        message_ids.append(str(payload.get("sid") or ""))
    return message_ids


def _telegram_chat_ids() -> list[str]:
    return [
        value.strip()
        for value in str(settings.TELEGRAM_CHAT_ID or "").split(",")
        if value.strip()
    ]


def send_telegram_proxy_alert(alert: ProxyInventoryAlert) -> list[str]:
    """Send a free push notification through the Telegram Bot API."""
    token = str(settings.TELEGRAM_BOT_TOKEN or "").strip()
    chat_ids = _telegram_chat_ids()
    if not token or not chat_ids:
        raise AlertConfigurationError(
            "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required."
        )

    endpoint = (
        "https://api.telegram.org/bot"
        f"{urllib.parse.quote(token, safe=':')}/sendMessage"
    )
    message_ids: list[str] = []
    for chat_id in chat_ids:
        request = urllib.request.Request(
            endpoint,
            data=urllib.parse.urlencode(
                {
                    "chat_id": chat_id,
                    "text": alert_message(alert),
                    "disable_web_page_preview": "true",
                }
            ).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=settings.PROXY_ALERT_TIMEOUT_SECONDS,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Telegram HTTP {exc.code}: {detail}") from exc
        if not payload.get("ok"):
            raise RuntimeError(
                f"Telegram API error: {str(payload.get('description') or payload)[:500]}"
            )
        message_ids.append(str((payload.get("result") or {}).get("message_id") or ""))
    return message_ids


def send_proxy_alert(alert: ProxyInventoryAlert) -> list[str]:
    provider = str(settings.PROXY_ALERT_PROVIDER or "telegram").strip().lower()
    if provider == "telegram":
        return send_telegram_proxy_alert(alert)
    if provider == "twilio":
        return send_twilio_proxy_alert(alert)
    raise AlertConfigurationError(
        "PROXY_ALERT_PROVIDER must be 'telegram' or 'twilio'."
    )
