from decouple import config
import logging

logger = logging.getLogger("sentry_init")


def init_sentry(environment: str | None = None) -> None:
    """
    Centralized Sentry initialization.

    - Reads configuration from environment variables / .env via decouple.
    - Does nothing if SENTRY_DSN is not provided.
    - Ensures send_default_pii is False in production by default.
    - Swallows ImportError if sentry-sdk is not installed.
    """
    try:
        import sentry_sdk
        from sentry_sdk.integrations.django import DjangoIntegration
    except ImportError:
        logger.debug("sentry-sdk not installed; skipping Sentry initialization.")
        return

    # Resolve environment and config values
    env = environment or config("ENVIRONMENT", default="development")
    dsn = config("SENTRY_DSN", default=None)
    if not dsn:
        logger.debug("SENTRY_DSN not set; skipping Sentry initialization.")
        return

    # sample / traces rates
    traces_sample_rate = config("SENTRY_TRACES_SAMPLE_RATE", default=None, cast=float)
    sample_rate = config("SENTRY_SAMPLE_RATE", default=None, cast=float)

    # Prefer traces_sample_rate when set, else sample_rate (backwards compat).
    traces_rate = traces_sample_rate if traces_sample_rate is not None else (sample_rate or 0.0)

    # send_default_pii: default to False in production for safety.
    # Allow enabling in non-production environments by setting SENTRY_SEND_PII or SENTRY_SEND_PII_DEV.
    send_default_pii_env = config("SENTRY_SEND_PII", default=None)
    send_default_pii_dev_flag = config("SENTRY_SEND_PII_DEV", default=False, cast=bool)

    if send_default_pii_env is not None:
        # decouple returns a string if present; cast to bool-like string handling:
        if isinstance(send_default_pii_env, str):
            send_default_pii = send_default_pii_env.lower() in ("1", "true", "yes", "y", "on")
        else:
            send_default_pii = bool(send_default_pii_env)
    else:
        send_default_pii = False if env == "production" else send_default_pii_dev_flag

    release = config("SENTRY_RELEASE", default=None)

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=env,
            integrations=[DjangoIntegration()],
            send_default_pii=send_default_pii,
            traces_sample_rate=traces_rate,
            release=release,
        )
        logger.info("Sentry initialized (environment=%s, send_default_pii=%s)", env, send_default_pii)
    except Exception as exc:  # pragma: no cover - extremely defensive
        # do not reveal DSN or sensitive data
        logger.exception("Failed to initialize Sentry: %s", str(exc))