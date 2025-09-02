import os
import sys
from pathlib import Path
from decouple import config
import dotenv

def main():
    BASE_DIR = Path(__file__).resolve().parent.parent
    sys.path.append(str(BASE_DIR / "backend" / "apps"))
    env_name = os.getenv("ENVIRONMENT", "development")
    env_file = BASE_DIR / f".env.{env_name}"
    if env_file.exists():
        dotenv.load_dotenv(dotenv_path=env_file)

    environment = config("ENVIRONMENT", default="development")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"config.settings.{environment}")

  # Initialize Sentry centrally (safe if sentry-sdk missing)
    try:
        from config.settings.sentry import init_sentry

        init_sentry(environment)
    except Exception:
        import logging

        logging.getLogger("sentry_init").exception("Unexpected error while initializing Sentry in manage.py")

# ======== Run Django Management Command ========
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()
