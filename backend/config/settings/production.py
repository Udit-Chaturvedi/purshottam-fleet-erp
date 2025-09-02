from decouple import config, Csv
from pathlib import Path
from .base import * # noqa: F401,F403
import logging

# ======== Debug & Hosts ========
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())
INTERNAL_IPS = config("INTERNAL_IPS", default="", cast=Csv())

# ======== Database ========
ORACLE_HOST = config("ORACLE_HOST")
ORACLE_PORT = config("ORACLE_PORT")
ORACLE_SERVICE_NAME = config("ORACLE_SERVICE_NAME", default=None)
ORACLE_SID = config("ORACLE_SID", default=None)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.oracle",
        "NAME": f"{ORACLE_HOST}:{ORACLE_PORT}/"
                f"{ORACLE_SERVICE_NAME if ORACLE_SERVICE_NAME else ORACLE_SID}",
        "USER": config("ORACLE_USER"),
        "PASSWORD": config("ORACLE_PASSWORD"),
        "ATOMIC_REQUESTS": True,
        "CONN_MAX_AGE": config("DB_CONN_MAX_AGE", default=60, cast=int),
        "OPTIONS": {
            **({"service_name": ORACLE_SERVICE_NAME} if ORACLE_SERVICE_NAME else {}),
            **({"sid": ORACLE_SID} if ORACLE_SID else {}),
            "encoding": "UTF-8",
        },
    }
}

# ======== Static & Media: Oracle Cloud Object Storage (S3-compatible) ========
STATICFILES_LOCATION = config("STATICFILES_LOCATION", default="static")
MEDIAFILES_LOCATION = config("MEDIAFILES_LOCATION", default="media")

AWS_ACCESS_KEY_ID = config("ORACLE_STORAGE_ACCESS_KEY")
AWS_SECRET_ACCESS_KEY = config("ORACLE_STORAGE_SECRET_KEY")
AWS_STORAGE_BUCKET_NAME = config("ORACLE_STORAGE_BUCKET")
AWS_S3_REGION_NAME = config("ORACLE_STORAGE_REGION", default="")
AWS_S3_ENDPOINT_URL = config("ORACLE_STORAGE_ENDPOINT", default="")
AWS_S3_SIGNATURE_VERSION = config("AWS_S3_SIGNATURE_VERSION", default="s3v4")
AWS_DEFAULT_ACL = config("AWS_DEFAULT_ACL", default="private")
AWS_S3_FILE_OVERWRITE = config("AWS_S3_FILE_OVERWRITE", default=False, cast=bool)
AWS_QUERYSTRING_AUTH = config("AWS_QUERYSTRING_AUTH", default=True, cast=bool)
AWS_S3_OBJECT_PARAMETERS = {"CacheControl": config("AWS_S3_CACHE_CONTROL", default="max-age=31536000, public")}
PRESIGNED_UPLOAD_EXPIRY = config("PRESIGNED_UPLOAD_EXPIRY", default=600, cast=int)

STATICFILES_STORAGE = config("STATICFILES_STORAGE", default="storages.backends.s3boto3.S3Boto3Storage")
DEFAULT_FILE_STORAGE = config("DEFAULT_FILE_STORAGE", default="storages.backends.s3boto3.S3Boto3Storage")

STATIC_ROOT = Path(config("STATIC_ROOT", default="/var/www/erp/static"))
MEDIA_ROOT = Path(config("MEDIA_ROOT", default="/var/www/erp/media"))

STATIC_URL = config("STATIC_URL", default=f"https://{AWS_STORAGE_BUCKET_NAME}/{STATICFILES_LOCATION}/")
MEDIA_URL = config("MEDIA_URL", default=f"https://{AWS_STORAGE_BUCKET_NAME}/{MEDIAFILES_LOCATION}/")

# ======== Security hardening ========
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", cast=bool)
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config("SECURE_HSTS_INCLUDE_SUBDOMAINS", cast=bool)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", cast=bool)
SECURE_CONTENT_TYPE_NOSNIFF = config("SECURE_CONTENT_TYPE_NOSNIFF", cast=bool)
SECURE_BROWSER_XSS_FILTER = config("SECURE_BROWSER_XSS_FILTER", cast=bool)

X_FRAME_OPTIONS = config("X_FRAME_OPTIONS")
SECURE_REFERRER_POLICY = config("SECURE_REFERRER_POLICY")
USE_X_FORWARDED_HOST = config("USE_X_FORWARDED_HOST", cast=bool)
USE_X_FORWARDED_PORT = config("USE_X_FORWARDED_PORT", cast=bool)
CSP_REPORT_ONLY = config("CSP_REPORT_ONLY", default=False, cast=bool)

# ======== Logging ========
DOCKERIZED = config("DOCKERIZED", default=True, cast=bool)
USE_JSON_LOGGING = config("USE_JSON_LOGGING", default=False, cast=bool)

LOG_DIR = Path(config("LOG_DIR", default="/var/log/erp"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

if DOCKERIZED:
    LOGGING["handlers"]["console"].update({"level": config("CONSOLE_LOG_LEVEL", default="INFO")})
    LOGGING["handlers"]["file"].update({"class": "logging.StreamHandler", "level": config("DJANGO_LOG_LEVEL", default="INFO")})
    LOGGING["handlers"]["audit_file"].update({"class": "logging.StreamHandler", "level": config("AUDIT_LOG_LEVEL", default="INFO")})
else:
    LOGGING["handlers"]["file"].update({
        "filename": str(LOG_DIR / config("APP_LOG", default="erp_app.log")),
        "maxBytes": config("LOG_MAX_BYTES", default=50 * 1024 * 1024, cast=int),
        "backupCount": config("LOG_BACKUP_COUNT", default=10, cast=int),
    })
    LOGGING["handlers"]["audit_file"].update({
        "filename": str(LOG_DIR / config("AUDIT_LOG", default="erp_audit.log")),
        "maxBytes": config("AUDIT_LOG_MAX_BYTES", default=100 * 1024 * 1024, cast=int),
        "backupCount": config("AUDIT_LOG_BACKUP_COUNT", default=12, cast=int),
    })

if USE_JSON_LOGGING:
    LOGGING["handlers"]["console"]["formatter"] = "json"
    LOGGING["handlers"]["file"]["formatter"] = "json"

LOGGING["loggers"]["django"].update({"handlers": ["console", "file"], "level": config("DJANGO_LOG_LEVEL", default="INFO")})
LOGGING["loggers"]["audit"].update({"handlers": ["audit_file"], "level": config("AUDIT_LOG_LEVEL", default="INFO")})
LOGGING["loggers"]["django.request"] = {"handlers": ["mail_admins", "console", "file"], "level": "ERROR", "propagate": False}

# ======== Gunicorn / deployment variables for CI/CD ========
GUNICORN_CMD = config("GUNICORN_CMD", default="gunicorn")
GUNICORN_MODULE = config("GUNICORN_MODULE", default="core.wsgi:application")
GUNICORN_WORKERS = config("GUNICORN_WORKERS", default=None)
GUNICORN_THREADS = config("GUNICORN_THREADS", default=None)
GUNICORN_TIMEOUT = config("GUNICORN_TIMEOUT", default=None)

if DEBUG:
    logging.warning("DEBUG is TRUE in production environment. Confirm this is intentional.")
    