from __future__ import annotations
import os
from celery import Celery
from celery.signals import worker_ready
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "controlserver.settings")
app = Celery("controlserver")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@worker_ready.connect
def prefill_proxy_pools_on_worker_start(**_kwargs):
    """Warm every configured country pool immediately after worker deployment."""
    app.send_task(
        "control.tasks.maintain_proxy_pools",
        kwargs={"force": True},
        queue="proxy-jobs",
    )
