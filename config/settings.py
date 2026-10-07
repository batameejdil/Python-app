from __future__ import annotations

import base64
import binascii
import hashlib
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, urlsplit


_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def env_value(key: str, default: str | None = None) -> str | None:
    value = os.getenv(key)
    if value is None or value == "":
        return default
    return value


def env_bool(key: str, default: bool = False) -> bool:
    value = env_value(key)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default


def env_int(key: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    value = env_value(key)
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def normalized_base_path() -> str:
    raw = (env_value("APP_BASE_PATH", "/") or "/").strip()
    if not raw or raw == "/":
        return "/"
    return "/" + raw.strip("/") + "/"


def _decode_key(raw: str | None) -> bytes | None:
    if not raw:
        return None
    if raw.startswith("base64:"):
        try:
            decoded = base64.b64decode(raw[7:], validate=True)
        except (ValueError, binascii.Error):
            return None
        return decoded[:32] if len(decoded) >= 32 else None
    if raw.startswith("hex:"):
        try:
            decoded = bytes.fromhex(raw[4:])
        except ValueError:
            return None
        return decoded[:32] if len(decoded) >= 32 else None
    if len(raw.encode("utf-8")) >= 32:
        return hashlib.sha256(raw.encode("utf-8")).digest()
    return None


def resolve_secret_key(production: bool) -> bytes:
    raw = env_value("SECRET_KEY") or env_value("APP_KEY")
    decoded = _decode_key(raw)
    if decoded is not None:
        return decoded
    if production:
        raise RuntimeError("SECRET_KEY or APP_KEY must provide at least 32 bytes of secret material in production.")
    return hashlib.sha256(b"localconnect-python-development-only-key").digest()


def database_uri(production: bool) -> str:
    explicit = env_value("DATABASE_URL")
    if explicit:
        normalized = explicit
        if normalized.startswith("mysql://"):
            normalized = "mysql+pymysql://" + normalized[len("mysql://"):]
        elif normalized.startswith("mariadb://"):
            normalized = "mysql+pymysql://" + normalized[len("mariadb://"):]
        if production and urlsplit(normalized).scheme.lower() != "mysql+pymysql":
            raise RuntimeError("DATABASE_URL must use MySQL/MariaDB via the mysql+pymysql driver in production.")
        return normalized

    host = env_value("DB_HOST", None if production else "127.0.0.1")
    port = env_value("DB_PORT", "3306") or "3306"
    name = env_value("DB_NAME", None if production else "localconnect_db")
    user = env_value("DB_USER", None if production else "root")
    password = env_value("DB_PASSWORD")
    if password is None:
        password = env_value("DB_PASS", None if production else "")

    if production and (not host or not name or not user or password is None):
        raise RuntimeError("Database configuration is incomplete. Configure DATABASE_URL or DB_HOST/DB_NAME/DB_USER/DB_PASSWORD.")

    host = host or "127.0.0.1"
    name = name or "localconnect_db"
    user = user or "root"
    password = password or ""
    return (
        f"mysql+pymysql://{quote_plus(user)}:{quote_plus(password)}@"
        f"{host}:{port}/{quote_plus(name)}?charset=utf8mb4"
    )


@dataclass(frozen=True)
class RuntimeSettings:
    app_env: str
    production: bool
    debug: bool
    app_url: str
    base_path: str
    force_https: bool
    trust_proxy: bool
    trusted_proxy_ips: tuple[str, ...]


def runtime_settings() -> RuntimeSettings:
    app_env = (env_value("APP_ENV", "development") or "development").strip().lower()
    production = app_env == "production"
    trusted = tuple(
        item.strip() for item in (env_value("TRUSTED_PROXY_IPS", "") or "").split(",") if item.strip()
    )
    return RuntimeSettings(
        app_env=app_env,
        production=production,
        debug=env_bool("APP_DEBUG", not production),
        app_url=(env_value("APP_URL", "") or "").rstrip("/"),
        base_path=normalized_base_path(),
        force_https=env_bool("FORCE_HTTPS", production),
        trust_proxy=env_bool("TRUST_PROXY", False),
        trusted_proxy_ips=trusted,
    )


def production_config_errors() -> list[str]:
    runtime = runtime_settings()
    if not runtime.production:
        return []

    errors: list[str] = []
    if not runtime.app_url:
        errors.append("APP_URL is required in production.")
    elif not runtime.app_url.lower().startswith("https://"):
        errors.append("APP_URL must use https:// in production.")

    try:
        resolve_secret_key(True)
    except RuntimeError as exc:
        errors.append(str(exc))

    try:
        database_uri(True)
    except RuntimeError as exc:
        errors.append(str(exc))

    db_user = env_value("DB_USER", "") or ""
    if not env_value("DATABASE_URL") and db_user.lower() == "root":
        errors.append("Use a dedicated least-privilege DB_USER in production.")

    password = env_value("DB_PASSWORD") or env_value("DB_PASS", "") or ""
    if not env_value("DATABASE_URL"):
        if not password:
            errors.append("DB_PASSWORD must not be blank in production.")
        elif "REPLACE_WITH_" in password:
            errors.append("DB_PASSWORD still contains a placeholder value.")

    if not env_bool("SESSION_COOKIE_SECURE", True):
        errors.append("SESSION_COOKIE_SECURE must be enabled in production.")
    if runtime.debug:
        errors.append("APP_DEBUG must be disabled in production.")
    if not runtime.force_https:
        errors.append("FORCE_HTTPS must be enabled in production.")
    if not env_bool("APP_ADMIN_MFA_REQUIRED", True):
        errors.append("APP_ADMIN_MFA_REQUIRED must be enabled in production.")
    if not env_bool("APP_REQUIRE_EMAIL_VERIFICATION", True):
        errors.append("APP_REQUIRE_EMAIL_VERIFICATION must be enabled in production.")
    if not env_bool("UPLOAD_REQUIRE_REENCODE", True):
        errors.append("UPLOAD_REQUIRE_REENCODE must be enabled in production.")

    storage_backend = (env_value("UPLOAD_STORAGE_BACKEND", "filesystem") or "filesystem").lower()
    storage_root = (env_value("UPLOAD_STORAGE_ROOT", "") or "").strip()
    if storage_backend != "filesystem":
        errors.append("UPLOAD_STORAGE_BACKEND must be filesystem for this deployment.")
    if env_bool("UPLOAD_DISK_REQUIRED", True):
        if not storage_root:
            errors.append("UPLOAD_STORAGE_ROOT is required when UPLOAD_DISK_REQUIRED is enabled.")
        elif not os.path.isabs(storage_root):
            errors.append("UPLOAD_STORAGE_ROOT must be an absolute path in production.")

    mail_driver = (env_value("APP_MAIL_DRIVER", "smtp") or "smtp").lower()
    if mail_driver == "smtp":
        if not env_value("SMTP_HOST"):
            errors.append("SMTP_HOST is required when APP_MAIL_DRIVER=smtp.")
        if not env_value("APP_MAIL_FROM"):
            errors.append("APP_MAIL_FROM is required when APP_MAIL_DRIVER=smtp.")

    trusted_hosts = [item.strip() for item in (env_value("TRUSTED_HOSTS", "") or "").split(",") if item.strip()]
    app_host = urlsplit(runtime.app_url).hostname if runtime.app_url else None
    if app_host and app_host not in trusted_hosts:
        trusted_hosts.append(app_host)
    if not trusted_hosts:
        errors.append("At least one TRUSTED_HOSTS entry (or APP_URL host) is required in production.")
    if runtime.trust_proxy and not runtime.trusted_proxy_ips:
        errors.append("TRUSTED_PROXY_IPS is required when TRUST_PROXY is enabled.")
    if (env_value("SECURITY_CSP_MODE", "enforce") or "enforce").lower() != "enforce":
        errors.append("SECURITY_CSP_MODE must be enforce in production.")
    if env_int("HSTS_MAX_AGE", 31536000) < 31536000:
        errors.append("HSTS_MAX_AGE should be at least 31536000 seconds in production.")

    return list(dict.fromkeys(errors))


class BaseConfig:
    runtime = runtime_settings()

    APP_ENV = runtime.app_env
    APP_URL = runtime.app_url
    APP_BASE_PATH = runtime.base_path
    DEBUG = runtime.debug
    TESTING = False

    SECRET_KEY = resolve_secret_key(False)

    SQLALCHEMY_DATABASE_URI = database_uri(False)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    _db_connect_args: dict[str, Any] = {
        "connect_timeout": env_int("DB_CONNECT_TIMEOUT", 10, minimum=1, maximum=120),
        "read_timeout": env_int("DB_READ_TIMEOUT", 30, minimum=1, maximum=300),
        "write_timeout": env_int("DB_WRITE_TIMEOUT", 30, minimum=1, maximum=300),
    }
    _db_uri_str = SQLALCHEMY_DATABASE_URI.lower() if SQLALCHEMY_DATABASE_URI else ""
    if env_bool("DB_SSL", "tidbcloud.com" in _db_uri_str or "aivencloud.com" in _db_uri_str):
        _db_connect_args["ssl"] = {}
    SQLALCHEMY_ENGINE_OPTIONS: dict[str, Any] = {
        "pool_pre_ping": True,
        "pool_recycle": env_int("DB_POOL_RECYCLE", 280, minimum=30, maximum=3600),
        "pool_size": env_int("DB_POOL_SIZE", 5, minimum=1, maximum=50),
        "max_overflow": env_int("DB_MAX_OVERFLOW", 10, minimum=0, maximum=100),
        "pool_timeout": env_int("DB_POOL_TIMEOUT", 30, minimum=1, maximum=120),
        "connect_args": _db_connect_args,
    }

    SESSION_COOKIE_NAME = env_value("SESSION_NAME", "localconnect_session") or "localconnect_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", runtime.production)
    SESSION_COOKIE_PATH = runtime.base_path
    SESSION_REFRESH_EACH_REQUEST = False
    SESSION_ABSOLUTE_TIMEOUT = env_int("SESSION_ABSOLUTE_TIMEOUT", 28800, minimum=300)
    PERMANENT_SESSION_LIFETIME = SESSION_ABSOLUTE_TIMEOUT
    SESSION_IDLE_TIMEOUT = env_int("SESSION_IDLE_TIMEOUT", 1800, minimum=300)
    SESSION_ROTATE_INTERVAL = env_int("SESSION_ROTATE_INTERVAL", 900, minimum=300)

    FORCE_HTTPS = runtime.force_https
    TRUST_PROXY = runtime.trust_proxy
    TRUSTED_PROXY_IPS = runtime.trusted_proxy_ips
    TRUSTED_PROXY_HOPS = env_int("TRUSTED_PROXY_HOPS", 1, minimum=1, maximum=5)
    _app_host = urlsplit(runtime.app_url).hostname if runtime.app_url else None
    _trusted_hosts = [item.strip() for item in (env_value("TRUSTED_HOSTS", "") or "").split(",") if item.strip()]
    if _app_host and _app_host not in _trusted_hosts:
        _trusted_hosts.append(_app_host)
    TRUSTED_HOSTS = _trusted_hosts or None
    PREFERRED_URL_SCHEME = "https" if runtime.production else "http"

    SECURITY_CSP_MODE = (env_value("SECURITY_CSP_MODE", "enforce" if runtime.production else "report-only") or "report-only").lower()
    HSTS_MAX_AGE = env_int("HSTS_MAX_AGE", 31536000, minimum=300, maximum=63072000)
    HSTS_INCLUDE_SUBDOMAINS = env_bool("HSTS_INCLUDE_SUBDOMAINS", False)
    HSTS_PRELOAD = env_bool("HSTS_PRELOAD", False)

    APP_REQUIRE_EMAIL_VERIFICATION = env_bool("APP_REQUIRE_EMAIL_VERIFICATION", True)
    APP_ADMIN_MFA_REQUIRED = env_bool("APP_ADMIN_MFA_REQUIRED", True)
    APP_MAIL_DRIVER = env_value("APP_MAIL_DRIVER", "log") or "log"
    APP_MAIL_FROM = env_value("APP_MAIL_FROM", "no-reply@example.com") or "no-reply@example.com"
    SMTP_HOST = env_value("SMTP_HOST", "") or ""
    SMTP_PORT = env_int("SMTP_PORT", 587, minimum=1, maximum=65535)
    SMTP_USERNAME = env_value("SMTP_USERNAME", "") or ""
    SMTP_PASSWORD = env_value("SMTP_PASSWORD", "") or ""
    SMTP_USE_TLS = env_bool("SMTP_USE_TLS", True)

    LOGIN_RATE_MAX_ATTEMPTS = env_int("LOGIN_RATE_MAX_ATTEMPTS", 5, minimum=1)
    LOGIN_RATE_WINDOW_SECONDS = env_int("LOGIN_RATE_WINDOW_SECONDS", 900, minimum=60)
    LOGIN_RATE_BLOCK_SECONDS = env_int("LOGIN_RATE_BLOCK_SECONDS", 900, minimum=60)

    UPLOAD_STORAGE_BACKEND = (env_value("UPLOAD_STORAGE_BACKEND", "filesystem") or "filesystem").lower()
    UPLOAD_STORAGE_ROOT = env_value("UPLOAD_STORAGE_ROOT", "") or ""
    UPLOAD_DISK_REQUIRED = env_bool("UPLOAD_DISK_REQUIRED", runtime.production)
    UPLOAD_MAX_FILE_BYTES = env_int("UPLOAD_MAX_FILE_BYTES", 3 * 1024 * 1024, minimum=64 * 1024, maximum=16 * 1024 * 1024)
    UPLOAD_MAX_DIMENSION = env_int("UPLOAD_MAX_DIMENSION", 6000, minimum=256)
    UPLOAD_MAX_PIXELS = env_int("UPLOAD_MAX_PIXELS", 20_000_000, minimum=1_000_000)
    UPLOAD_REQUIRE_REENCODE = env_bool("UPLOAD_REQUIRE_REENCODE", True)
    UPLOAD_PUBLIC_CACHE_SECONDS = env_int("UPLOAD_PUBLIC_CACHE_SECONDS", 86400, minimum=0, maximum=31536000)
    STATIC_CACHE_SECONDS = env_int("STATIC_CACHE_SECONDS", 3600 if runtime.production else 0, minimum=0, maximum=31536000)

    PAYMENT_RAZORPAY_KEY_ID = env_value("PAYMENT_RAZORPAY_KEY_ID", "") or ""
    PAYMENT_RAZORPAY_KEY_SECRET: str = env_value("PAYMENT_RAZORPAY_KEY_SECRET", "") or ""
    PAYMENT_RAZORPAY_WEBHOOK_SECRET = env_value("PAYMENT_RAZORPAY_WEBHOOK_SECRET", "") or ""
    PAYMENT_RAZORPAY_WEBHOOK_IP_ALLOWLIST = tuple(
        item.strip()
        for item in (env_value("PAYMENT_RAZORPAY_WEBHOOK_IP_ALLOWLIST", "") or "").split(",")
        if item.strip()
    )
    PAYMENT_ALLOW_LIVE = env_bool("PAYMENT_ALLOW_LIVE", False)
    PAYMENT_CHECKOUT_TTL_SECONDS = env_int("PAYMENT_CHECKOUT_TTL_SECONDS", 1800, minimum=300)

    PAGINATION_MAX_PAGE = env_int("PAGINATION_MAX_PAGE", 1000, minimum=1)
    PERF_METRICS_ENABLED = env_bool("PERF_METRICS_ENABLED", False)
    PERF_METRICS_MAX_BYTES = env_int("PERF_METRICS_MAX_BYTES", 10_485_760, minimum=1_048_576)
    PERF_TARGET_P95_MS = env_int("PERF_TARGET_P95_MS", 750, minimum=1)
    PERF_TARGET_PEAK_MB = env_int("PERF_TARGET_PEAK_MB", 32, minimum=1)
    PERF_MIN_SAMPLES = env_int("PERF_MIN_SAMPLES", 100, minimum=1)
    PAYMENT_WORKER_BATCH_MAX = env_int("PAYMENT_WORKER_BATCH_MAX", 20, minimum=1)
    PAYMENT_WORKER_MAX_ATTEMPTS = env_int("PAYMENT_WORKER_MAX_ATTEMPTS", 5, minimum=1)
    PAYMENT_RECONCILIATION_QUEUE_MAX = env_int("PAYMENT_RECONCILIATION_QUEUE_MAX", 10000, minimum=1)

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = env_int("CSRF_TIME_LIMIT", 3600, minimum=300, maximum=86400)
    WTF_CSRF_SSL_STRICT = runtime.production
    MAX_CONTENT_LENGTH = env_int("MAX_REQUEST_BYTES", 8 * 1024 * 1024, minimum=1 * 1024 * 1024, maximum=32 * 1024 * 1024)
    MAX_FORM_MEMORY_SIZE = env_int("MAX_FORM_MEMORY_BYTES", 512 * 1024, minimum=64 * 1024, maximum=4 * 1024 * 1024)
    MAX_FORM_PARTS = env_int("MAX_FORM_PARTS", 200, minimum=20, maximum=1000)
    SEND_FILE_MAX_AGE_DEFAULT = STATIC_CACHE_SECONDS
    SLOW_REQUEST_MS = env_int("SLOW_REQUEST_MS", 1500, minimum=100, maximum=60000)


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SECRET_KEY = b"test-only-localconnect-secret-key-material"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    WTF_CSRF_ENABLED = False
    FORCE_HTTPS = False
    SESSION_COOKIE_SECURE = False
