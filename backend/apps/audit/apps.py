from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
    verbose_name = "Audit & Activity Logs"

    def ready(self):
        load_signals("audit")