from __future__ import annotations

import secrets

from django.core.management.base import BaseCommand, CommandError

from control.models import YSBridgeAgent


class Command(BaseCommand):
    help = "Create or rotate a YSBrowser bridge agent token. The raw token is shown once."

    def add_arguments(self, parser):
        parser.add_argument("--name", default="Primary office PC")
        parser.add_argument("--rotate", action="store_true")

    def handle(self, *args, **options):
        name = str(options["name"] or "").strip()
        if not name:
            raise CommandError("Agent name cannot be empty.")
        agent = YSBridgeAgent.objects.filter(name=name).first()
        if agent is not None and not options["rotate"]:
            raise CommandError(
                "That agent already exists. Pass --rotate to invalidate its old token."
            )
        raw_token = "ysb_" + secrets.token_urlsafe(48)
        if agent is None:
            agent = YSBridgeAgent(name=name)
        agent.active = True
        agent.set_token(raw_token)
        agent.save()
        self.stdout.write(self.style.SUCCESS(f"YS bridge agent ready: {agent.name}"))
        self.stdout.write("Copy this token into Setup-YSBridge.ps1 now; it cannot be recovered later:")
        self.stdout.write(raw_token)
