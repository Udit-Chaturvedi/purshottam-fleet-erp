from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class CustomersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.customers'
    verbose_name = "Customer Management"

    def ready(self):
        load_signals("customers")