from __future__ import annotations

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache_utils import bump_access_audit_cache_version
from .models import BootstrapAudit, ConfigBundle


@receiver(post_save, sender=BootstrapAudit)
@receiver(post_delete, sender=BootstrapAudit)
@receiver(post_save, sender=ConfigBundle)
@receiver(post_delete, sender=ConfigBundle)
def invalidate_access_audit_cache(**_kwargs) -> None:
    bump_access_audit_cache_version()
