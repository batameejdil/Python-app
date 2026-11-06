from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import ssl
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, request
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.core import PlatformActivity, User
from models.marketplace import BusinessProfile, Notification, ProviderProfile
from models.security import AdminMfa, AuthRateLimit, AuthToken

LOGGER = logging.getLogger(__name__)
ALLOWED_REGISTRATION_ROLES = {"customer", "provider", "business"}
TOKEN_PURPOSES = {"password_reset", "email_verify"}
PHONE_RE = re.compile(r"^[0-9+() .-]{7,25}$")
SELECTOR_RE = re.compile(r"^[a-f0-9]{16}$")
VALIDATOR_RE = re.compile(r"^[a-f0-9]{64}$")
TOTP_RE = re.compile(r"^\d{6}$")


def clean_text(value: object, max_length: int, required: bool = False, label: str = "Field") -> str:
    text = value.strip() if isinstance(value, str) else ""
    if required and not text:
        raise ValueError(f"{label} is required.")
    if len(text) > max_length:
        raise ValueError(f"{label} is too long.")
    if "\x00" in text:
        raise ValueError(f"{label} contains invalid characters.")
    return text


def valid_phone_or_empty(phone: str) -> bool:
    return not phone or bool(PHONE_RE.fullmatch(phone))


def normalize_email(value: object) -> str:
    return clean_text(value, 190, True, "Email").lower()


def is_valid_email(value: str) -> bool:
    if len(value) > 190 or "@" not in value:
        return False
    local, _, domain = value.rpartition("@")
    return bool(local and domain and "." in domain and " " not in value)




def validate_new_password(password: str) -> None:
    # bcrypt only incorporates the first 72 bytes. Reject longer new/reset
    # passwords so two visibly different passwords cannot authenticate as the
    # same credential. Existing legacy hashes remain login-compatible.
    byte_length = len((password or "").encode("utf-8"))
    if byte_length < 12:
        raise ValueError("Password must be at least 12 characters.")
    if byte_length > 72:
        raise ValueError("Password is too long. Use at most 72 UTF-8 bytes.")

def password_hash(password: str) -> str:
    # bcrypt remains PHP password_verify()-compatible during the migration window.
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def password_verify(password: str, encoded: str) -> bool:
    if not encoded:
        return False
    candidate = encoded.encode("ascii", "ignore")
    if candidate.startswith(b"$2y$"):
        candidate = b"$2b$" + candidate[4:]
    try:
        return bcrypt.checkpw(password.encode("utf-8"), candidate)
    except (ValueError, TypeError):
        return False


def password_needs_rehash(encoded: str) -> bool:
    match = re.match(r"^\$2[aby]\$(\d\d)\$", encoded or "")
    return not match or int(match.group(1)) < 12


def dashboard_for(role: str) -> str:
    return {
        "customer": "/customer/dashboard.php",
        "provider": "/provider/dashboard.php",
        "business": "/business/dashboard.php",
        "admin": "/admin/index.php",
    }.get(role, "/")


def safe_admin_return(path: str, fallback: str = "admin/index.php") -> str:
    path = (path or "").strip().lstrip("/")
    if not path or not path.startswith("admin/") or ".." in path or "\\" in path or "://" in path or "\r" in path or "\n" in path:
        return fallback
    return path


def app_key_bytes() -> bytes:
    # Prefer APP_KEY to preserve PHP-encrypted MFA records; fall back to SECRET_KEY.
    raw = os.getenv("APP_KEY") or os.getenv("SECRET_KEY") or ""
    if raw.startswith("base64:"):
        try:
            decoded = base64.b64decode(raw[7:], validate=True)
            if len(decoded) >= 32:
                return decoded[:32]
        except ValueError:
            pass
    elif raw.startswith("hex:"):
        try:
            decoded = bytes.fromhex(raw[4:])
            if len(decoded) >= 32:
                return decoded[:32]
        except ValueError:
            pass
    elif len(raw.encode("utf-8")) >= 32:
        return hashlib.sha256(raw.encode("utf-8")).digest()
    if current_app.config.get("TESTING"):
        secret = current_app.config["SECRET_KEY"]
        return hashlib.sha256(secret if isinstance(secret, bytes) else str(secret).encode()).digest()
    if current_app.config.get("APP_ENV") == "production":
        raise RuntimeError("APP_KEY/SECRET_KEY is missing or invalid for encrypted secrets.")
    return hashlib.sha256(b"localconnect-python-development-only-key").digest()


def app_hmac(value: str, purpose: str) -> str:
    return hmac.new(app_key_bytes(), (purpose + "\0" + value).encode(), hashlib.sha256).hexdigest()


def client_ip() -> str:
    remote = request.remote_addr or "unknown"
    if current_app.config.get("TRUST_PROXY"):
        trusted = set(current_app.config.get("TRUSTED_PROXY_IPS") or ())
        if "*" in trusted or remote in trusted:
            chain = [item.strip() for item in (request.headers.get("X-Forwarded-For") or "").split(",") if item.strip()]
            if chain:
                # Reverse-proxy chains append addresses. Select from the trusted
                # end rather than the attacker-controllable left edge.
                hops = max(1, min(5, int(current_app.config.get("TRUSTED_PROXY_HOPS", 1))))
                return chain[max(0, len(chain) - hops)]
    return remote


def client_ip_hash() -> str:
    return app_hmac(client_ip(), "ip")


def security_log(event: str, **context: object) -> None:
    safe: dict[str, object] = {}
    for key, value in context.items():
        if re.search(r"pass|secret|token|authorization|cookie", key, re.I):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
    LOGGER.warning("security event=%s context=%s", re.sub(r"[^a-zA-Z0-9_.-]", "_", event)[:120], safe)


def log_activity(actor_id: int | None, action: str, target_type: str | None = None, target_id: int | None = None, details: str | None = None) -> None:
    # Isolate audit failures with a savepoint so a logging problem does not abort
    # the surrounding business transaction. This mirrors the legacy fail-open
    # audit helper while keeping the main database change transactional.
    try:
        with db.session.begin_nested():
            db.session.add(PlatformActivity(actor_id=actor_id, action=action, target_type=target_type, target_id=target_id, details=(details or "")[:500] or None))
            db.session.flush()
    except SQLAlchemyError:
        security_log("audit_write_failed", action=action)


def unread_notification_count(user_id: int) -> int:
    return int(db.session.scalar(select(db.func.count(Notification.id)).where(Notification.user_id == user_id, Notification.is_read == 0)) or 0)


def register_user(*, name: str, email: str, phone: str, password: str, role: str, city: str, state: str) -> User:
    if role not in ALLOWED_REGISTRATION_ROLES:
        raise ValueError("Please select a valid account type.")
    if len(name) < 2:
        raise ValueError("Please enter your full name.")
    if not is_valid_email(email):
        raise ValueError("Please enter a valid email address.")
    if not valid_phone_or_empty(phone):
        raise ValueError("Please enter a valid phone number.")
    validate_new_password(password)
    if db.session.scalar(select(User.id).where(User.email == email).limit(1)):
        raise ValueError("An account with this email already exists.")

    needs_verify = bool(current_app.config.get("APP_REQUIRE_EMAIL_VERIFICATION", True))
    user = User(
        name=name,
        email=email,
        phone=phone or None,
        password_hash=password_hash(password),
        role=role,
        status="pending" if needs_verify else "active",
        city=city or None,
        state=state or None,
        email_verified_at=None if needs_verify else datetime.now(),
    )
    db.session.add(user)
    db.session.flush()
    if role == "provider":
        db.session.add(ProviderProfile(user_id=user.id, verification_status="pending"))
    elif role == "business":
        db.session.add(BusinessProfile(user_id=user.id, verification_status="pending"))
    log_activity(user.id, "account_registered", "user", user.id)
    db.session.commit()
    return user


def _rate_keys(action: str, email: str, *, login: bool = False) -> list[str]:
    action = re.sub(r"[^a-z0-9_-]", "", action.lower()) or "auth-action"
    email = email.strip().lower()
    if login:
        return [app_hmac(email, "login-email"), app_hmac(client_ip_hash(), "login-ip")]
    return [app_hmac(action + "\0" + email, "auth-action-email"), app_hmac(action + "\0" + client_ip_hash(), "auth-action-ip")]


def rate_check(action: str, email: str, *, login: bool = False) -> int:
    now = datetime.now()
    maximum = 0
    for key in _rate_keys(action, email, login=login):
        row = db.session.get(AuthRateLimit, key)
        if row and row.blocked_until:
            maximum = max(maximum, int((row.blocked_until - now).total_seconds()))
    return max(0, maximum)


def rate_hit(action: str, email: str, limit: int, window_seconds: int, block_seconds: int, *, login: bool = False) -> None:
    now = datetime.now()
    limit = max(1, min(20, limit))
    window_seconds = max(60, min(86400, window_seconds))
    block_seconds = max(60, min(86400, block_seconds))
    try:
        for key in _rate_keys(action, email, login=login):
            row = db.session.execute(select(AuthRateLimit).where(AuthRateLimit.bucket_hash == key).with_for_update()).scalar_one_or_none()
            if row is None:
                row = AuthRateLimit(bucket_hash=key, attempts=1, window_started_at=now)
                if limit <= 1:
                    row.blocked_until = now + timedelta(seconds=block_seconds)
                db.session.add(row)
                continue
            if row.blocked_until and row.blocked_until > now:
                continue
            if (now - row.window_started_at).total_seconds() <= window_seconds:
                row.attempts += 1
            else:
                row.attempts = 1
                row.window_started_at = now
                row.blocked_until = None
            if row.attempts >= limit:
                row.blocked_until = now + timedelta(seconds=block_seconds)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        security_log("auth_rate_write_failed", action=action)


def login_rate_failure(email: str) -> None:
    rate_hit(
        "login", email,
        int(current_app.config["LOGIN_RATE_MAX_ATTEMPTS"]),
        int(current_app.config["LOGIN_RATE_WINDOW_SECONDS"]),
        int(current_app.config["LOGIN_RATE_BLOCK_SECONDS"]),
        login=True,
    )


def login_rate_success(email: str) -> None:
    try:
        db.session.execute(delete(AuthRateLimit).where(AuthRateLimit.bucket_hash.in_(_rate_keys("login", email, login=True))))
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()


def create_auth_token(user_id: int, purpose: str, ttl_seconds: int) -> dict[str, str]:
    if purpose not in TOKEN_PURPOSES:
        raise ValueError("Invalid token purpose.")
    selector = secrets.token_hex(8)
    validator = secrets.token_hex(32)
    expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
    db.session.execute(delete(AuthToken).where(AuthToken.user_id == user_id, AuthToken.purpose == purpose, AuthToken.used_at.is_(None)))
    db.session.add(AuthToken(user_id=user_id, purpose=purpose, selector=selector, token_hash=hashlib.sha256(validator.encode()).hexdigest(), expires_at=expires_at, requested_ip_hash=client_ip_hash()))
    db.session.commit()
    return {"selector": selector, "token": validator, "expires_at": expires_at.isoformat()}


def find_valid_auth_token(purpose: str, selector: str, validator: str, *, lock: bool = False) -> AuthToken | None:
    if purpose not in TOKEN_PURPOSES or not SELECTOR_RE.fullmatch(selector or "") or not VALIDATOR_RE.fullmatch(validator or ""):
        return None
    stmt = select(AuthToken).where(
        AuthToken.purpose == purpose,
        AuthToken.selector == selector,
        AuthToken.used_at.is_(None),
        AuthToken.expires_at > datetime.now(),
    ).limit(1)
    if lock:
        stmt = stmt.with_for_update()
    row = db.session.scalar(stmt)
    if not row:
        return None
    return row if hmac.compare_digest(row.token_hash, hashlib.sha256(validator.encode()).hexdigest()) else None


def absolute_url(path: str) -> str:
    origin = (current_app.config.get("APP_URL") or "").rstrip("/")
    if not origin:
        origin = request.url_root.rstrip("/")
    return f"{origin}/{path.lstrip('/')}"


def send_app_email(to: str, subject: str, body: str) -> bool:
    driver = str(current_app.config.get("APP_MAIL_DRIVER", "disabled")).lower()
    sender = str(current_app.config.get("APP_MAIL_FROM", ""))
    if driver == "log" and current_app.config.get("APP_ENV") != "production":
        directory = Path(current_app.root_path) / "storage"
        directory.mkdir(mode=0o700, exist_ok=True)
        with (directory / "mail-development.log").open("a", encoding="utf-8") as fh:
            fh.write(f"--- {datetime.now().isoformat()} ---\nTo: {to}\nSubject: {subject}\n{body}\n\n")
        return True
    if driver not in {"smtp", "mail"}:
        return False
    host = current_app.config.get("SMTP_HOST")
    if not host or not sender or not is_valid_email(to) or not is_valid_email(sender):
        return False
    port = int(current_app.config.get("SMTP_PORT", 587))
    username = current_app.config.get("SMTP_USERNAME") or ""
    password = current_app.config.get("SMTP_PASSWORD") or ""
    use_tls = bool(current_app.config.get("SMTP_USE_TLS", True))
    msg = EmailMessage()
    msg["From"] = f"LocalConnect <{sender}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException):
        security_log("mail_delivery_failed")
        return False


def base32_encode_secret(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def base32_decode_secret(value: str) -> bytes:
    cleaned = re.sub(r"[^A-Z2-7]", "", value.upper())
    return base64.b32decode(cleaned + "=" * ((8 - len(cleaned) % 8) % 8), casefold=True)


def totp_code(secret: str, at_time: int | None = None) -> str:
    counter = int((at_time if at_time is not None else time.time()) // 30)
    digest = hmac.new(base32_decode_secret(secret), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


def verify_totp(secret: str, code: str, last_used_step: int | None = None) -> int | None:
    if not TOTP_RE.fullmatch(code or ""):
        return None
    step = int(time.time() // 30)
    for delta in (-1, 0, 1):
        candidate = step + delta
        if last_used_step is not None and candidate <= last_used_step:
            continue
        if hmac.compare_digest(totp_code(secret, candidate * 30), code):
            return candidate
    return None


def encrypt_sensitive(plaintext: str, algorithm: str = "sodium_secretbox") -> dict[str, str]:
    key = app_key_bytes()
    if algorithm == "sodium_secretbox":
        box = SecretBox(key)
        nonce = secrets.token_bytes(SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(plaintext.encode(), nonce).ciphertext
        return {"ciphertext": base64.b64encode(encrypted).decode(), "nonce": base64.b64encode(nonce).decode(), "alg": algorithm}
    nonce = secrets.token_bytes(12)
    cipher_with_tag = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return {"ciphertext": base64.b64encode(cipher_with_tag).decode(), "nonce": base64.b64encode(nonce).decode(), "alg": "aes-256-gcm"}


def decrypt_sensitive(ciphertext: str, nonce: str, algorithm: str) -> str:
    key = app_key_bytes()
    raw = base64.b64decode(ciphertext, validate=True)
    iv = base64.b64decode(nonce, validate=True)
    try:
        if algorithm == "sodium_secretbox":
            return SecretBox(key).decrypt(raw, iv).decode()
        if algorithm == "aes-256-gcm":
            return AESGCM(key).decrypt(iv, raw, None).decode()
    except (CryptoError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Secret decryption failed.") from exc
    raise ValueError("Secret encryption algorithm is unavailable.")


def admin_mfa_record(user_id: int) -> AdminMfa | None:
    return db.session.get(AdminMfa, user_id)


def admin_mfa_needed(user: User) -> bool:
    if user.role != "admin":
        return False
    return admin_mfa_record(user.id) is not None or bool(current_app.config.get("APP_ADMIN_MFA_REQUIRED", True))


def mfa_secret_from_record(record: AdminMfa) -> str:
    return decrypt_sensitive(record.secret_ciphertext, record.secret_nonce, record.encryption_alg)


def otpauth_uri(secret: str, email: str) -> str:
    issuer = quote("LocalConnect", safe="")
    account = quote(email, safe="")
    return f"otpauth://totp/{issuer}:{account}?secret={quote(secret, safe='')}&issuer={issuer}&digits=6&period=30"


from dataclasses import dataclass


@dataclass
class EnvAdminConfig:
    identifier: str
    email: str
    password: str
    name: str


def get_env_admins() -> list[EnvAdminConfig]:
    admins: list[EnvAdminConfig] = []
    seen: set[str] = set()

    def _register(raw_id: str | None, raw_pass: str | None, raw_name: str | None = None):
        if not raw_id or not raw_pass:
            return
        identifier = str(raw_id).strip()
        password = str(raw_pass).strip()
        if not identifier or not password:
            return
        ident_key = identifier.lower()
        if ident_key in seen:
            return
        seen.add(ident_key)
        email = ident_key if "@" in identifier else f"{ident_key}@admin.local"
        name = (raw_name or "").strip() or identifier.capitalize()
        admins.append(EnvAdminConfig(
            identifier=ident_key,
            email=email,
            password=password,
            name=name,
        ))

    # Single admin env vars
    _register(
        os.getenv("ADMIN_EMAIL") or os.getenv("ADMIN_USER") or os.getenv("ADMIN_ID"),
        os.getenv("ADMIN_PASSWORD") or os.getenv("ADMIN_PASS"),
        os.getenv("ADMIN_NAME") or "Administrator",
    )

    # Numbered admin env vars (ADMIN_1_EMAIL, ADMIN_2_EMAIL, ADMIN_3_EMAIL, up to 20)
    for i in range(1, 21):
        raw_id = (
            os.getenv(f"ADMIN_{i}_EMAIL")
            or os.getenv(f"ADMIN{i}_EMAIL")
            or os.getenv(f"ADMIN_{i}_USER")
            or os.getenv(f"ADMIN{i}_USER")
            or os.getenv(f"ADMIN_{i}_ID")
            or os.getenv(f"ADMIN{i}_ID")
        )
        raw_pass = (
            os.getenv(f"ADMIN_{i}_PASSWORD")
            or os.getenv(f"ADMIN{i}_PASSWORD")
            or os.getenv(f"ADMIN_{i}_PASS")
            or os.getenv(f"ADMIN{i}_PASS")
        )
        raw_name = (
            os.getenv(f"ADMIN_{i}_NAME")
            or os.getenv(f"ADMIN{i}_NAME")
            or f"Admin {i}"
        )
        _register(raw_id, raw_pass, raw_name)

    # Combined variable ADMIN_USERS="admin1:pass1:Name 1,admin2:pass2:Name 2"
    raw_users = os.getenv("ADMIN_USERS") or ""
    if raw_users.strip():
        for chunk in raw_users.split(","):
            parts = [c.strip() for c in chunk.split(":") if c.strip()]
            if len(parts) >= 2:
                _register(parts[0], parts[1], parts[2] if len(parts) > 2 else None)

    return admins


def sync_env_admins(app=None) -> list[User]:
    """Sync all admins configured in environment variables into the database."""
    admins = get_env_admins()
    if not admins:
        return []
    synced: list[User] = []
    for admin in admins:
        user = db.session.scalar(
            select(User).where(
                (User.email == admin.email)
                | (User.email == admin.identifier)
            ).limit(1)
        )
        if user is None:
            user = User(
                name=admin.name,
                email=admin.email,
                password_hash=password_hash(admin.password),
                role="admin",
                status="active",
                email_verified_at=datetime.now(),
                session_version=1,
            )
            db.session.add(user)
        else:
            user.role = "admin"
            user.status = "active"
            if not user.email_verified_at:
                user.email_verified_at = datetime.now()
            if not password_verify(admin.password, user.password_hash):
                user.password_hash = password_hash(admin.password)
            if admin.name:
                user.name = admin.name
        synced.append(user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        LOGGER.exception("Failed to sync environment admin accounts into database.")
    return synced


def find_matching_env_admin(identity: str, password: str) -> User | None:
    """Check if the provided credentials match any environment-configured admin."""
    if not identity or not password:
        return None
    ident = identity.strip().lower()
    admins = get_env_admins()
    for admin in admins:
        if ident in (admin.identifier, admin.email):
            if hmac.compare_digest(admin.password, password) or password_verify(password, password_hash(admin.password)):
                user = db.session.scalar(
                    select(User).where(
                        (User.email == admin.email) | (User.email == admin.identifier)
                    ).limit(1)
                )
                if user is None:
                    user = User(
                        name=admin.name,
                        email=admin.email,
                        password_hash=password_hash(admin.password),
                        role="admin",
                        status="active",
                        email_verified_at=datetime.now(),
                        session_version=1,
                    )
                    db.session.add(user)
                else:
                    user.role = "admin"
                    user.status = "active"
                    if not user.email_verified_at:
                        user.email_verified_at = datetime.now()
                    if not password_verify(admin.password, user.password_hash):
                        user.password_hash = password_hash(admin.password)
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                return user
    return None

