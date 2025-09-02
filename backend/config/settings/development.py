from pathlib import Path
from decouple import config, Csv
from .base import * # noqa: F401,F403

# ======== Debug & Hosts ========
DEBUG = config("DEBUG", default=True, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="127.0.0.1,localhost", cast=Csv())
INTERNAL_IPS = config("INTERNAL_IPS", default="127.0.0.1,localhost", cast=Csv())

# ======== Database ========
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("DEV_DB_NAME", default="erp_dev"),
        "USER": config("DEV_DB_USER", default="postgres"),
        "PASSWORD": config("DEV_DB_PASSWORD", default="postgres"),
        "HOST": config("DEV_DB_HOST", default="127.0.0.1"),
        "PORT": config("DEV_DB_PORT", default="5432"),
        "ATOMIC_REQUESTS": True,
        "CONN_MAX_AGE": 0,
    }
}

# ======== Static & Media ========
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"

# ======== Logging verbosity (DEBUG) ========
LOG_DIR = Path(config("LOG_DIR", default=str(BASE_DIR / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
# console handler for debug
LOGGING["handlers"]["console"].update({"level": "DEBUG", "formatter": "request_id"})
LOGGING["handlers"]["file"].update({
    "level": "DEBUG",
    "filename": str(LOG_DIR / "erp_dev_app.log"),
    "maxBytes": 10 * 1024 * 1024,
    "backupCount": 5,
})
LOGGING["handlers"]["audit_file"].update({
    "level": "DEBUG",
    "filename": str(LOG_DIR / "erp_dev_audit.log"),
    "maxBytes": 20 * 1024 * 1024,
    "backupCount": 5,
})

LOGGING["loggers"]["django"].update({"handlers": ["console", "file"], "level": "DEBUG"})
LOGGING["loggers"]["audit"].update({"handlers": ["audit_file"], "level": "DEBUG"})

# ======== Security for dev ========
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", cast=bool)
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", cast=bool)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", cast=bool)
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", cast=int)
SECURE_CONTENT_TYPE_NOSNIFF = config("SECURE_CONTENT_TYPE_NOSNIFF", cast=bool)
SECURE_BROWSER_XSS_FILTER = config("SECURE_BROWSER_XSS_FILTER", cast=bool)
X_FRAME_OPTIONS = config("X_FRAME_OPTIONS")

# ======== Docker dev flag ========
DOCKERIZED = config("DOCKERIZED", default=False, cast=bool)
if DOCKERIZED:
    LOGGING["handlers"]["file"]["class"] = "logging.StreamHandler"
    LOGGING["handlers"]["audit_file"]["class"] = "logging.StreamHandler"