from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    verbose_name = "Core System"

    def ready(self):
        load_signals("core")