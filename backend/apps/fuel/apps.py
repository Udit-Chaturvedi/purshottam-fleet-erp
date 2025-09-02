from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class FuelConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.fuel'
    verbose_name = "Fuel Management"

    def ready(self):
        load_signals("fuel")