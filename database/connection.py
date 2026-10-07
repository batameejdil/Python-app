from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

import pymysql
from dotenv import load_dotenv

load_dotenv()


_TRUE = {"1", "true", "yes", "on", "required"}


@dataclass(frozen=True)
class DatabaseConnectionSettings:
    host: str
    port: int
    database: str
    user: str
    password: str
    ssl_enabled: bool
    connect_timeout: int
    read_timeout: int
    write_timeout: int


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return default if value in (None, "") else value


def _bool_env(name: str, default: bool = False) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE


def _int_env(name: str, default: int, minimum: int = 1, maximum: int = 120) -> int:
    try:
        value = int(_env(name, str(default)) or default)
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _settings_from_url(url: str) -> DatabaseConnectionSettings:
    normalized = url
    if normalized.startswith("mysql+pymysql://"):
        normalized = "mysql://" + normalized[len("mysql+pymysql://"):]
    if normalized.startswith("mariadb://"):
        normalized = "mysql://" + normalized[len("mariadb://"):]
    parsed = urlparse(normalized)
    if parsed.scheme != "mysql":
        raise RuntimeError("DATABASE_URL/MIGRATION_DATABASE_URL must use a MySQL/MariaDB URL.")
    database = unquote(parsed.path.lstrip("/"))
    if not parsed.hostname or not database or parsed.username is None or parsed.password is None:
        raise RuntimeError("Database URL must include host, database, user, and password.")
    query = parse_qs(parsed.query)
    ssl_value = (query.get("ssl", [""])[0] or query.get("ssl-mode", [""])[0]).lower()
    return DatabaseConnectionSettings(
        host=parsed.hostname,
        port=parsed.port or 3306,
        database=database,
        user=unquote(parsed.username),
        password=unquote(parsed.password),
        ssl_enabled=ssl_value in _TRUE or _bool_env("DB_SSL", False),
        connect_timeout=_int_env("DB_CONNECT_TIMEOUT", 10),
        read_timeout=_int_env("DB_READ_TIMEOUT", 30),
        write_timeout=_int_env("DB_WRITE_TIMEOUT", 30),
    )


def connection_settings(*, migration: bool = False) -> DatabaseConnectionSettings:
    url = _env("MIGRATION_DATABASE_URL") if migration else None
    url = url or _env("DATABASE_URL")
    if url:
        return _settings_from_url(url)

    password = _env("DB_PASSWORD")
    if password is None:
        password = _env("DB_PASS")
    required = {
        "DB_HOST": _env("DB_HOST"),
        "DB_NAME": _env("DB_NAME"),
        "DB_USER": _env("DB_MIGRATION_USER") if migration else _env("DB_USER"),
        "DB_PASSWORD": _env("DB_MIGRATION_PASSWORD") if migration else password,
    }
    if migration:
        required["DB_USER"] = required["DB_USER"] or _env("DB_USER")
        required["DB_PASSWORD"] = required["DB_PASSWORD"] or password
    missing = [name for name, value in required.items() if value in (None, "")]
    if missing:
        raise RuntimeError("Missing database configuration: " + ", ".join(missing))

    return DatabaseConnectionSettings(
        host=str(required["DB_HOST"]),
        port=int(_env("DB_PORT", "3306") or "3306"),
        database=str(required["DB_NAME"]),
        user=str(required["DB_USER"]),
        password=str(required["DB_PASSWORD"]),
        ssl_enabled=_bool_env("DB_SSL", False),
        connect_timeout=_int_env("DB_CONNECT_TIMEOUT", 10),
        read_timeout=_int_env("DB_READ_TIMEOUT", 30),
        write_timeout=_int_env("DB_WRITE_TIMEOUT", 30),
    )


def connect(*, migration: bool = False):
    settings = connection_settings(migration=migration)
    kwargs = dict(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password,
        database=settings.database,
        charset="utf8mb4",
        autocommit=True,
        connect_timeout=settings.connect_timeout,
        read_timeout=settings.read_timeout,
        write_timeout=settings.write_timeout,
        cursorclass=pymysql.cursors.DictCursor,
    )
    if settings.ssl_enabled or "tidbcloud.com" in settings.host:
        import ssl
        kwargs["ssl"] = ssl.create_default_context()
    return pymysql.connect(**kwargs)
