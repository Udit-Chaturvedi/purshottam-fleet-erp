from pathlib import Path
from datetime import timedelta
from decouple import config, Csv
import warnings
import logging

# ======== Paths & Core ========
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APP_DIR = BASE_DIR / "apps"

SECRET_KEY = config("SECRET_KEY")
ENVIRONMENT = config("ENVIRONMENT", default="development")

# ======== Applications ========
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_filters",
    "simple_history",
    "django_celery_beat",
    "django_celery_results",
    "storages",
    "django_otp",
    "django_otp.plugins.otp_static",
    "django_otp.plugins.otp_totp",
    "axes",
    "csp",
    "health_check",
    "health_check.db",
    "health_check.cache",
    "health_check.storage",
    "health_check.contrib.celery",
    "health_check.contrib.psutil",
]

LOCAL_APPS = [
    "apps.audit.apps.AuditConfig",
    "apps.challans.apps.ChallansConfig",
    "apps.core.apps.CoreConfig",
    "apps.customers.apps.CustomersConfig",
    "apps.drivers.apps.DriversConfig",
    "apps.fuel.apps.FuelConfig",
    "apps.integrations.apps.IntegrationsConfig",
    "apps.notifications.apps.NotificationsConfig",
    "apps.payroll.apps.PayrollConfig",
    "apps.reports.apps.ReportsConfig",
    "apps.scheduler.apps.SchedulerConfig",
    "apps.users.apps.UsersConfig",
    "apps.utils.apps.UtilsConfig",
    "apps.vehicles.apps.VehiclesConfig",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ======== Middleware ========
MIDDLEWARE = [
    "request_id.middleware.RequestIdMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "axes.middleware.AxesMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "simple_history.middleware.HistoryRequestMiddleware",
    "csp.middleware.CSPMiddleware",
]

# ======== URL / WSGI / ASGI ========
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ======== Request ID ========
REQUEST_ID_HEADER = "HTTP_X_REQUEST_ID"
REQUEST_ID_RESPONSE_HEADER = "X-Request-ID"
GENERATE_REQUEST_ID_IF_NOT_IN_HEADER = True

# ======== Django Simple History ========
SIMPLE_HISTORY_HISTORY_CHANGE_REASON_REQUIRED = False
SIMPLE_HISTORY_FILEFIELD_TO_CHARFIELD = True

# ======== Templates ========
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ======== Authentication / Users / Session ========
AUTH_USER_MODEL = "users.User"
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    # {"NAME": "apps.users.validators.CustomComplexityValidator"},
]

# ========  Config ========
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
SESSION_COOKIE_AGE = config("SESSION_COOKIE_AGE", default=60*60*8, cast=int)
SESSION_EXPIRE_AT_BROWSER_CLOSE = config("SESSION_EXPIRE_AT_BROWSER_CLOSE", default=False, cast=bool)
SESSION_COOKIE_HTTPONLY = config("SESSION_COOKIE_HTTPONLY", default=True, cast=bool)
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", default=False, cast=bool)

# ======== Internationalization / Timezone ========
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

# ======== Upload constraints ========
DATA_UPLOAD_MAX_MEMORY_SIZE = config("DATA_UPLOAD_MAX_MEMORY_SIZE", default=50 * 1024 * 1024, cast=int)
FILE_UPLOAD_MAX_MEMORY_SIZE = config("FILE_UPLOAD_MAX_MEMORY_SIZE", default=10 * 1024 * 1024, cast=int)
FILE_UPLOAD_PERMISSIONS = 0o644
ALLOWED_DOCUMENT_EXTENSIONS = [".jpg", ".jpeg", ".png", ".pdf"]

# ======== DRF / JWT ========
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework_simplejwt.authentication.JWTAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": config("DRF_PAGE_SIZE", default=20, cast=int),
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": config("DRF_THROTTLE_USER", default="1000/day"),
        "anon": config("DRF_THROTTLE_ANON", default="200/day"),
    },
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.openapi.AutoSchema",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=config("JWT_ACCESS_MINUTES", default=15, cast=int)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=config("JWT_REFRESH_DAYS", default=7, cast=int)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": config("JWT_SIGNING_KEY", default=SECRET_KEY),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_USER_CLASS": "apps.users.models.User",
}

# ======== CORS & CSRF ========
CORS_ALLOWED_ORIGINS = config("CORS_ALLOWED_ORIGINS", default="", cast=Csv())
CORS_ALLOW_ALL_ORIGINS = config("CORS_ALLOW_ALL_ORIGINS", default=False, cast=bool)
CORS_ALLOW_CREDENTIALS = config("CORS_ALLOW_CREDENTIALS", default=True, cast=bool)
CORS_ALLOW_HEADERS = config("CORS_ALLOW_HEADERS", default="content-type,authorization", cast=Csv())
CORS_ALLOW_METHODS = config("CORS_ALLOW_METHODS", default="GET,POST,PUT,PATCH,DELETE,OPTIONS", cast=Csv())
CORS_EXPOSE_HEADERS = config("CORS_EXPOSE_HEADERS", default="", cast=Csv())
CORS_PREFLIGHT_MAX_AGE = config("CORS_PREFLIGHT_MAX_AGE", default=86400, cast=int)
CSRF_TRUSTED_ORIGINS = config("CSRF_TRUSTED_ORIGINS", default="", cast=Csv())
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=False, cast=bool)
CSRF_COOKIE_HTTPONLY = config("CSRF_COOKIE_HTTPONLY", default=False, cast=bool)

# ======== Redis/ Cache/ Celery ========
REDIS_HOST = config("REDIS_HOST", default="127.0.0.1")
REDIS_PORT = config("REDIS_PORT", default="6379")
REDIS_PASSWORD = config("REDIS_PASSWORD", default=None)
REDIS_DB_DEFAULT = config("REDIS_DB_DEFAULT", default=0, cast=int)
REDIS_DB_CELERY = config("REDIS_DB_CELERY", default=1, cast=int)
REDIS_AUTH = f":{REDIS_PASSWORD}@" if REDIS_PASSWORD else ""
REDIS_URL = f"redis://{REDIS_AUTH}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB_DEFAULT}"
CELERY_REDIS_URL = f"redis://{REDIS_AUTH}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB_CELERY}"

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
        "TIMEOUT": config("CACHE_DEFAULT_TIMEOUT", default=300, cast=int),
    }
}

CELERY_BROKER_URL = CELERY_REDIS_URL
CELERY_RESULT_BACKEND = "django-db"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True
CELERY_ACKS_LATE = True
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_WORKER_MAX_TASKS_PER_CHILD = config("CELERY_WORKER_MAX_TASKS_PER_CHILD", default=100, cast=int)
CELERY_TASK_TIME_LIMIT = config("CELERY_TASK_TIME_LIMIT", default=30 * 60, cast=int)
CELERY_WORKER_PREFETCH_MULTIPLIER = config("CELERY_WORKER_PREFETCH_MULTIPLIER", default=1, cast=int)
CELERY_WORKER_CONCURRENCY = config("CELERY_WORKER_CONCURRENCY", default=4, cast=int)

# ======== Health checks ========
ALLOWED_HEALTH_IPS = config("ALLOWED_HEALTH_IPS", default="", cast=Csv())
HEALTH_CHECK_DB = config("HEALTH_CHECK_DB", default=True, cast=bool)
HEALTH_CHECK_CACHE = config("HEALTH_CHECK_CACHE", default=True, cast=bool)
HEALTH_CHECK_STORAGE = config("HEALTH_CHECK_STORAGE", default=True, cast=bool)
HEALTH_CHECK_DISK_USAGE_MIN = config("HEALTH_CHECK_DISK_USAGE_MIN", default=10, cast=int)
HEALTH_CHECK_MEMORY_MIN = config("HEALTH_CHECK_MEMORY_MIN", default=100, cast=int)

# ======== Logging ========
try:
    LOG_DIR = Path(config("LOG_DIR", default=str(BASE_DIR / "logs")))
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    LOG_DIR = BASE_DIR / "logs"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    warnings.warn(f"LOG_DIR fallback used due to error: {e}")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"request_id": {"()": "request_id.logging.RequestIdFilter"}},
    "formatters": {
        "verbose": {"format": "[{asctime}] {levelname} {name}:{lineno} {message}", "style": "{"},
        "audit": {"format": "[{asctime}] AUDIT {levelname} [user:{user} ip:{ip} agent:{agent}] {message}", "style": "{"},
        "request_id": {"format": "[{asctime}] {levelname} {request_id} {name}:{lineno} {message}", "style": "{"},
        "json": {"()": "pythonjsonlogger.jsonlogger.JsonFormatter", "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "request_id", "filters": ["request_id"], "level": "INFO"},
        "file": {"level": "INFO", "class": "logging.handlers.RotatingFileHandler", "filename": str(LOG_DIR / "erp_app.log"), "maxBytes": 50 * 1024 * 1024, "backupCount": 10, "formatter": "verbose"},
        "audit_file": {"level": "INFO", "class": "logging.handlers.RotatingFileHandler", "filename": str(LOG_DIR / "erp_audit.log"), "maxBytes": 100 * 1024 * 1024, "backupCount": 12, "formatter": "audit"},
        "mail_admins": {"level": "ERROR", "class": "django.utils.log.AdminEmailHandler"},
    },
    "loggers": {
        "django": {"handlers": ["console", "file"], "level": "INFO", "propagate": True},
        "django.request": {"handlers": ["mail_admins", "console", "file"], "level": "ERROR", "propagate": False},
        "audit": {"handlers": ["audit_file"], "level": "INFO", "propagate": False},
    },
}

# ======== CSP (Content Security Policy) ========
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": tuple(config("CSP_DEFAULT_SRC", default="'self'").replace(",", " ").split()),
        "script-src": tuple(config("CSP_SCRIPT_SRC", default="'self'").replace(",", " ").split()),
        "style-src": tuple(config("CSP_STYLE_SRC", default="'self'").replace(",", " ").split()),
        "font-src": tuple(config("CSP_FONT_SRC", default="'self'").replace(",", " ").split()),
        "img-src": tuple(config("CSP_IMG_SRC", default="'self'").replace(",", " ").split()),
        "connect-src": tuple(config("CSP_CONNECT_SRC", default="'self'").replace(",", " ").split()),
        "frame-ancestors": tuple(config("CSP_FRAME_ANCESTORS", default="'none'").replace(",", " ").split()),
    }
}

# ======== AXES (Security) ========
AXES_FAILURE_LIMIT = config("AXES_FAILURE_LIMIT", default=5, cast=int)
AXES_COOLOFF_TIME = config("AXES_COOLOFF_TIME", default=1, cast=int)
AXES_ENABLED = config("AXES_ENABLED", default=True, cast=bool)

# ======== Email (SMTP / Transactional) ========
EMAIL_BACKEND = config("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT", cast=int)
EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_USE_SSL = config("EMAIL_USE_SSL", default=False, cast=bool) 
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="no-reply@erp.example.com")
SERVER_EMAIL = config("SERVER_EMAIL", default="server-error@erp.example.com")

# ======== OTP / MSG91 / Password reset ========
MSG91_AUTH_KEY = config("MSG91_AUTH_KEY")
MSG91_SENDER_ID = config("MSG91_SENDER_ID")
MSG91_OTP_TEMPLATE_ID = config("MSG91_OTP_TEMPLATE_ID")

OTP_LENGTH = config("OTP_LENGTH", default=6, cast=int)
OTP_EXPIRY_MINUTES = config("OTP_EXPIRY_MINUTES", default=10, cast=int)
OTP_REQUEST_COOLDOWN = config("OTP_REQUEST_COOLDOWN", default=60, cast=int)

# ======== Admin Notification ========
raw_admins = config("ADMINS", default="", cast=str)
ADMINS = tuple(tuple(admin.strip().split(":")) for admin in raw_admins.split(",")) if raw_admins else ()

# ======== Sentry Configuration ========
SENTRY_DSN = config("SENTRY_DSN", default=None)
SENTRY_ENVIRONMENT = config("ENVIRONMENT", default="development")
SENTRY_SAMPLE_RATE = config("SENTRY_SAMPLE_RATE", default=0.1, cast=float)

# ======== Default Primary Key ========
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"