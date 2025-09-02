from django.apps import AppConfig
from apps.utils.signals_loader import load_signals


class SchedulerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scheduler'
    verbose_name = "Task Scheduler & Automation"

    def ready(self):
        load_signals("scheduler")