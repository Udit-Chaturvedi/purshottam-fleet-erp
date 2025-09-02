from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class ChallansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.challans'
    verbose_name = "Challan Management"

    def ready(self):
        load_signals("challans")
