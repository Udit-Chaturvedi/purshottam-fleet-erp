from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class DriversConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.drivers'
    verbose_name = "Driver Management"

    def ready(self):
        load_signals("drivers")
