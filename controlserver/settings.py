from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import dj_database_url
from celery.schedules import crontab
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
# OPTIX has its own runtime root. The legacy variable is only a temporary
# compatibility fallback, so this server can never share release storage or a
# SQLite database with the existing automation-control deployment by mistake.
RUNTIME_DATA_DIR = Path(
    os.getenv("OPTIX_DATA_DIR", os.getenv("PROXYPILOT_DATA_DIR", str(BASE_DIR)))
).resolve()
RUNTIME_DATA_DIR.mkdir(parents=True, exist_ok=True)
ENV_FILE = Path(
    os.getenv("PROXYPILOT_ENV_FILE", str(RUNTIME_DATA_DIR / ".env"))
).resolve()
if ENV_FILE.is_file():
    load_dotenv(ENV_FILE, override=False)
elif (BASE_DIR / ".env").is_file():
    load_dotenv(BASE_DIR / ".env", override=False)

def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


DEBUG = env_bool("DEBUG", False)
LOCAL_TESTING_MODE = env_bool("LOCAL_TESTING_MODE", False)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
CONFIG_ENCRYPTION_SECRET = os.getenv("CONFIG_ENCRYPTION_SECRET", "")
if DEBUG:
    SECRET_KEY = SECRET_KEY or "development-only-secret-key-change-me"
    CONFIG_ENCRYPTION_SECRET = (
        CONFIG_ENCRYPTION_SECRET or "development-only-encryption-secret-change-me"
    )
elif not SECRET_KEY or not CONFIG_ENCRYPTION_SECRET:
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY and CONFIG_ENCRYPTION_SECRET are required."
    )

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS")
render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
railway_hostname = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
platform_hostnames = [name for name in (render_hostname, railway_hostname) if name]
if railway_hostname:
    platform_hostnames.append("healthcheck.railway.app")
for hostname in platform_hostnames:
    if hostname not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(hostname)
if DEBUG and not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]

CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS")
for hostname in (render_hostname, railway_hostname):
    if hostname:
        origin = f"https://{hostname}"
        if origin not in CSRF_TRUSTED_ORIGINS:
            CSRF_TRUSTED_ORIGINS.append(origin)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "control.apps.ControlConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "controlserver.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]
WSGI_APPLICATION = "controlserver.wsgi.application"
ASGI_APPLICATION = "controlserver.asgi.application"

DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").strip().lower()
if DB_ENGINE == "mysql":
    required_mysql_vars = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST")
    missing_mysql_vars = [name for name in required_mysql_vars if not os.getenv(name)]
    if missing_mysql_vars:
        raise ImproperlyConfigured(
            "Missing required MySQL variables: " + ", ".join(missing_mysql_vars)
        )

    mysql_options = {
        "charset": "utf8mb4",
        "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10")),
        "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
    }
    db_ssl_ca = os.getenv("DB_SSL_CA", "").strip()
    db_ssl_mode = os.getenv("DB_SSL_MODE", "").strip().upper()
    if db_ssl_ca:
        mysql_options["ssl"] = {"ca": db_ssl_ca}
    if db_ssl_mode:
        mysql_options["ssl_mode"] = db_ssl_mode
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.environ["DB_NAME"],
            "USER": os.environ["DB_USER"],
            "PASSWORD": os.environ["DB_PASSWORD"],
            "HOST": os.environ["DB_HOST"],
            "PORT": os.getenv("DB_PORT", "3306"),
            "OPTIONS": mysql_options,
            "CONN_MAX_AGE": int(os.getenv("DB_CONN_MAX_AGE", "60")),
            "CONN_HEALTH_CHECKS": True,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": RUNTIME_DATA_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = RUNTIME_DATA_DIR / "staticfiles"
MEDIA_URL = "media/"
MEDIA_ROOT = RUNTIME_DATA_DIR / "media"
desktop_release_root_override = os.getenv("DESKTOP_RELEASE_ROOT", "").strip()
DESKTOP_RELEASE_ROOT = (
    Path(desktop_release_root_override).resolve()
    if desktop_release_root_override
    else RUNTIME_DATA_DIR / "private-desktop-releases"
)
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if DEBUG
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        )
    },
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

TRUST_PROXY_HEADERS = env_bool(
    "TRUST_PROXY_HEADERS", bool(render_hostname or railway_hostname)
)
CLOUDFLARE_ORIGIN_SECRET = os.getenv("CLOUDFLARE_ORIGIN_SECRET", "").strip()
# Explicitly approved deployment mode: the desktop obtains its public IPv4
# from ipv4.test-ipv6.com and binds it to the exact authorized device ID.
TRUST_APP_REPORTED_IPV4 = env_bool("TRUST_APP_REPORTED_IPV4", True)
REQUIRE_REPORTED_IP_MATCH = env_bool("REQUIRE_REPORTED_IP_MATCH", True)
BOOTSTRAP_TOKEN_MAX_AGE = int(os.getenv("BOOTSTRAP_TOKEN_MAX_AGE", "300"))
BOOTSTRAP_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BOOTSTRAP_RATE_LIMIT_PER_MINUTE", "30")
)

# Creating every provider/country/region pool for every bundle produced
# hundreds of millions of unused rows on large deployments. Pools are now
# created on demand by the proxy-job API/admin. This switch exists only for
# small installations that explicitly want eager country-level provisioning.
AUTO_CREATE_PROXY_POOL_TARGETS = env_bool(
    "AUTO_CREATE_PROXY_POOL_TARGETS", False
)
# App requests and the periodic maintainer never generate inventory unless an
# operator explicitly enables these switches. Manual admin refills remain
# available regardless of these settings.
AUTO_GENERATE_PROXY_ON_DEMAND = env_bool(
    "AUTO_GENERATE_PROXY_ON_DEMAND", False
)
AUTO_REFILL_PROXY_POOLS = env_bool("AUTO_REFILL_PROXY_POOLS", False)
PROXY_EXIT_IP_COOLDOWN_SECONDS = int(
    os.getenv("PROXY_EXIT_IP_COOLDOWN_SECONDS", str(25 * 60 * 60))
)
PROXY_REFILL_STALE_SECONDS = int(os.getenv("PROXY_REFILL_STALE_SECONDS", "900"))
# Every deployed device has its own browser group, so the account/group FIFO
# lease is optional. Direct mode avoids stale leases delaying profile starts.
PROFILE_CREATE_SERIALIZATION_ENABLED = env_bool(
    "PROFILE_CREATE_SERIALIZATION_ENABLED", False
)

# OPTIX uses Warrior only as a private proxy supply service. Desktop clients
# never receive this URL/secret and continue talking exclusively to OPTIX.
WARRIOR_PROXY_BRIDGE_URL = os.getenv("WARRIOR_PROXY_BRIDGE_URL", "").strip()
WARRIOR_PROXY_BRIDGE_SECRET = os.getenv("WARRIOR_PROXY_BRIDGE_SECRET", "").strip()
WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS = int(
    os.getenv("WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS", "30")
)

PROXY_ALERT_ENABLED = env_bool(
    "PROXY_ALERT_ENABLED", env_bool("PROXY_ALERT_SMS_ENABLED", False)
)
PROXY_ALERT_PROVIDER = os.getenv("PROXY_ALERT_PROVIDER", "telegram").strip().lower()
PROXY_ALERT_SMS_TO = os.getenv("PROXY_ALERT_SMS_TO", "").strip()
PROXY_ALERT_COOLDOWN_SECONDS = int(
    os.getenv("PROXY_ALERT_COOLDOWN_SECONDS", "1800")
)
PROXY_ALERT_TIMEOUT_SECONDS = int(
    os.getenv(
        "PROXY_ALERT_TIMEOUT_SECONDS",
        os.getenv("PROXY_ALERT_SMS_TIMEOUT_SECONDS", "10"),
    )
)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
TWILIO_MESSAGING_SERVICE_SID = os.getenv(
    "TWILIO_MESSAGING_SERVICE_SID", ""
).strip()

CELERY_BROKER_URL = os.getenv("REDIS_URL", "").strip()
CELERY_RESULT_BACKEND = CELERY_BROKER_URL
CELERY_TASK_DEFAULT_QUEUE = "proxy-jobs"
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_TASK_IGNORE_RESULT = True

# Server-only, read-only YS metadata import. No profile data is sent upstream.
YS_CATALOG_SYNC_ENABLED = env_bool("YS_CATALOG_SYNC_ENABLED", False)
YS_UPSTREAM_API_KEY = os.getenv("YS_UPSTREAM_API_KEY", "").strip()

# Share cache state across Gunicorn workers. REDIS_CACHE_URL may point to a
# dedicated Redis service/database; otherwise DB 1 is derived from REDIS_URL
# so Celery queue data and Django cache keys remain isolated.
REDIS_CACHE_URL = os.getenv("REDIS_CACHE_URL", "").strip()
if not REDIS_CACHE_URL and CELERY_BROKER_URL:
    parsed_redis = urlsplit(CELERY_BROKER_URL)
    REDIS_CACHE_URL = urlunsplit(
        (
            parsed_redis.scheme,
            parsed_redis.netloc,
            "/1",
            parsed_redis.query,
            parsed_redis.fragment,
        )
    )
if REDIS_CACHE_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_CACHE_URL,
            "KEY_PREFIX": "optix-control",
            "TIMEOUT": 300,
            "OPTIONS": {
                "socket_connect_timeout": 3,
                "socket_timeout": 3,
            },
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "optix-control-local",
        }
    }
CELERY_BEAT_SCHEDULE = {
    "ys-browser-catalog-sync-ist": {
        "task": "control.tasks.sync_ys_browser_catalogs",
        "schedule": crontab(hour="8,12,16,20", minute=0),
        "options": {"queue": "catalog-sync", "expires": 3600},
    },
    "maintain-proxy-pools": {
        "task": "control.tasks.maintain_proxy_pools",
        "schedule": 300.0,
    },
    "morning-provider-geography-sync": {
        "task": "control.tasks.sync_proxy_geography",
        "schedule": crontab(hour=5, minute=10),
    },
    "morning-proxy-pool-prefill": {
        "task": "control.tasks.maintain_proxy_pools",
        "schedule": crontab(hour=5, minute=30),
        "kwargs": {"force": True},
    },
}
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
DESKTOP_RELEASE_MAX_BYTES = int(
    os.getenv("DESKTOP_RELEASE_MAX_BYTES", str(200 * 1024 * 1024))
)
DESKTOP_COMPONENT_MAX_BYTES = int(
    os.getenv("DESKTOP_COMPONENT_MAX_BYTES", str(800 * 1024 * 1024))
)

if TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "control": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
