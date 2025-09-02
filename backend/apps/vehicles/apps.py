from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class VehiclesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.vehicles'
    verbose_name = "Fleet & Vehicle Management"

    def ready(self):
        load_signals("vehicles")