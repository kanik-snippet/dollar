from django.apps import AppConfig


class ControlConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "control"
    verbose_name = "OPTIX Control"

    def ready(self) -> None:
        from . import signals  # noqa: F401
