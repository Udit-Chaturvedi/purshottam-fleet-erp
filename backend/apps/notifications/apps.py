from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.notifications'
    verbose_name = "Notifications & Alerts"

    def ready(self):
        load_signals("notifications")