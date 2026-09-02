from __future__ import annotations

import os

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible


@deconstructible
class PrivateDesktopReleaseStorage(FileSystemStorage):
    """Filesystem storage outside MEDIA_ROOT with no public URL surface."""

    def __init__(self):
        super().__init__(location=None, base_url=None)

    @property
    def base_location(self) -> str:
        return str(settings.DESKTOP_RELEASE_ROOT)

    @property
    def location(self) -> str:
        return os.path.abspath(self.base_location)

    def url(self, name: str) -> str:
        raise ValueError("Desktop release artifacts have no public URL.")


private_desktop_release_storage = PrivateDesktopReleaseStorage()
