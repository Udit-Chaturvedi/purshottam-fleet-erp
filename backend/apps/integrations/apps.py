from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class IntegrationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.integrations'
    verbose_name = "External Integrations"

    def ready(self):
        load_signals("integrations")