import importlib
import logging
import sys
from django.apps import apps

logger = logging.getLogger("django")

def load_signals(app_label: str) -> None:
    """
    Dynamically load the signals.py module of an installed app.
    """
    if not apps.is_installed(f"apps.{app_label}"):
        logger.warning(f"App '{app_label}' is not installed or not in INSTALLED_APPS.")
        return

    module_name = f"apps.{app_label}.signals"

    if module_name in sys.modules:
        logger.debug(f"Signals for '{app_label}' already loaded (by sys.modules).")
        return

    try:
        importlib.import_module(module_name)
        logger.info(f"Loaded signals module for app '{app_label}'.")
    except ModuleNotFoundError as e:
        if e.name and e.name.endswith("signals"):
            logger.debug(f"No signals.py found for '{app_label}'. Skipping.")
        else:
            logger.exception(f"Failed loading signals for '{app_label}': {e}")
    except Exception as exc:
        logger.exception(f"Error loading signals for '{app_label}': {exc}")
