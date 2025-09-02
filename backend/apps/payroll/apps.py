from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class PayrollConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.payroll'
    verbose_name = "Payroll & Salary Management"

    def ready(self):
        load_signals("payroll")