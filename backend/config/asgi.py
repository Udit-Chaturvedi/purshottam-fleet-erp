import os
import sys
from pathlib import Path
from decouple import config
import dotenv

# ======== Load environment file ========
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR / "apps"))

env_name = os.getenv("ENVIRONMENT", "development")
env_file = BASE_DIR / f".env.{env_name}"
if env_file.exists():
    dotenv.load_dotenv(dotenv_path=env_file)

# ======== Django settings ========
environment = config("ENVIRONMENT", default="development")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"config.settings.{environment}")

# ======== Initialize Sentry (centralized) ========
# Import and call the centralized initializer; doesn't raise if sentry-sdk missing.
try:
    from config.settings.sentry import init_sentry

    init_sentry(environment)
except Exception:
    # avoid crashing ASGI startup for any unexpected error
    import logging

    logging.getLogger("sentry_init").exception("Unexpected error while initializing Sentry in ASGI.")

# ======== ASGI application ========
from django.core.asgi import get_asgi_application

application = get_asgi_application()
