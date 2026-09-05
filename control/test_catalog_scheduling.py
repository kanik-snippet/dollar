"""Standalone scheduler tests; no external calls or deployment actions."""
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command, CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from .models import BrowserCatalogSnapshot


class ScheduledCatalogCommandTests(SimpleTestCase):
    @patch("control.management.commands.sync_ys_catalogs.sync_catalogs", return_value=[{"status": "disabled"}])
    def test_scheduled_run_respects_enable_flag(self, sync):
        output = StringIO()
        call_command("sync_ys_catalogs", scheduled=True, stdout=output)
        sync.assert_called_once_with(force=False)
        self.assertIn("disabled", output.getvalue())

    @patch("control.management.commands.sync_ys_catalogs.sync_catalogs", return_value=[{"status": "updated"}])
    def test_manual_run_remains_explicit(self, sync):
        call_command("sync_ys_catalogs", stdout=StringIO())
        sync.assert_called_once_with(force=True)

    @patch("control.management.commands.sync_ys_catalogs.sync_catalogs", return_value=[{"status": "failed", "error": "Sanitized error."}])
    def test_partial_failure_has_nonzero_command_result(self, sync):
        with self.assertRaises(CommandError):
            call_command("sync_ys_catalogs", scheduled=True, stdout=StringIO())


class ScheduledCatalogDisabledTests(TestCase):
    @override_settings(YS_CATALOG_SYNC_ENABLED=False)
    @patch("control.browser_catalog.upstream_post")
    def test_disabled_scheduled_command_creates_no_rows_and_makes_no_request(self, upstream):
        output = StringIO()
        call_command("sync_ys_catalogs", scheduled=True, stdout=output)
        upstream.assert_not_called()
        self.assertFalse(BrowserCatalogSnapshot.objects.exists())
        self.assertIn("disabled", output.getvalue())

    @patch("control.management.commands.sync_ys_catalogs.sync_catalogs")
    def test_status_remains_read_only(self, sync):
        call_command("sync_ys_catalogs", status=True, stdout=StringIO())
        sync.assert_not_called()


class StandaloneSchedulerAssetTests(SimpleTestCase):
    def test_runner_is_bounded_locked_and_does_not_start_other_jobs(self):
        root = Path(__file__).resolve().parent.parent
        runner = (root / "deploy" / "run_ys_catalog_sync.sh").read_text()
        self.assertIn("08:00|12:00|16:00|20:00", runner)
        self.assertIn("TZ=Asia/Kolkata", runner)
        self.assertIn("/usr/bin/flock -n -E 75", runner)
        self.assertIn("--kill-after=10s 720s", runner)
        self.assertIn("sync_ys_catalogs --scheduled > /dev/null 2>&1", runner)
        self.assertNotIn("celery", runner)
        self.assertNotIn("maintain_proxy", runner)
        self.assertNotRegex(runner, r"(?m)^\s*(?:source|\.)\s")

    def test_timer_uses_explicit_ist_and_existing_unprivileged_app_user(self):
        root = Path(__file__).resolve().parent.parent
        timer = (root / "deploy" / "dollar-ys-catalog-sync.timer").read_text()
        service = (root / "deploy" / "dollar-ys-catalog-sync.service").read_text()
        self.assertIn("OnCalendar=*-*-* 08,12,16,20:00:00 Asia/Kolkata", timer)
        self.assertIn("Persistent=false", timer)
        self.assertIn("User=dolla5434", service)
        self.assertIn("Type=oneshot", service)
        self.assertIn("TimeoutStartSec=750", service)
