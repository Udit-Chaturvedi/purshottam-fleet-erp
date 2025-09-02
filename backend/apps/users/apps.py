from django.apps import AppConfig
from apps.utils.signals_loader import load_signals

class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = "User Management & Access Control"

    def ready(self):
        load_signals("users")
