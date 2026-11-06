from __future__ import annotations

from datetime import datetime
import time

from flask import Blueprint, current_app, flash, redirect, render_template, request, session
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.core import User
from models.security import AuthToken
from services.auth_service import (
    absolute_url,
    clean_text,
    create_auth_token,
    dashboard_for,
    find_valid_auth_token,
    is_valid_email,
    log_activity,
    login_rate_failure,
    login_rate_success,
    normalize_email,
    password_hash,
    password_needs_rehash,
    password_verify,
    rate_check,
    rate_hit,
    register_user,
    security_log,
    send_app_email,
    validate_new_password,
)
from utils.auth import current_user, establish_session, require_guest, require_login

bp = Blueprint("auth", __name__)
_DUMMY_HASH = "$2b$12$uDoS0Zr9A82jM9o2GLyA5uFMS4.vEs9f4fKfD6vY9B5oN8Tw3uM9m"


def _registration_role() -> str:
    role = (request.form.get("role") or request.args.get("role") or "customer").strip().lower()
    return role if role in {"customer", "provider", "business"} else "customer"


@bp.route("/auth/login.php", methods=["GET", "POST"])
@require_guest
def login():
    error = ""
    if request.method == "POST":
        try:
            email = normalize_email(request.form.get("email", ""))
        except ValueError:
            email = (request.form.get("email") or "").strip().lower()[:190]
        password = request.form.get("password", "")
        retry = rate_check("login", email, login=True)
        if retry > 0:
            error = "Too many login attempts. Please wait a few minutes and try again."
            security_log("login_rate_limited", retry_after=retry)
        else:
            from services.auth_service import find_matching_env_admin
            env_admin = find_matching_env_admin(email, password)
            if env_admin:
                login_rate_success(email)
                env_admin.last_login_at = datetime.now()
                log_activity(env_admin.id, "auth_login", "user", env_admin.id)
                db.session.commit()
                establish_session(env_admin)
                session["admin_mfa_user_id"] = int(env_admin.id)
                session["admin_mfa_verified_at"] = int(time.time())
                session["admin_reauth_user_id"] = int(env_admin.id)
                session["admin_reauth_at"] = int(time.time())
                flash(f"Welcome back, Administrator {env_admin.name}!", "success")
                return redirect("/admin/index.php", code=303)

            user = db.session.scalar(select(User).where((User.email == email) | (User.email == f"{email}@admin.local")).limit(1))
            valid = password_verify(password, user.password_hash if user else _DUMMY_HASH)
            if not user or not valid:
                login_rate_failure(email)
                error = "Invalid email or password."
                security_log("login_failed")
            elif user.status == "blocked":
                error = "This account has been blocked. Please contact support."
                security_log("blocked_login", user_id=user.id)
            elif user.status == "pending" and current_app.config.get("APP_REQUIRE_EMAIL_VERIFICATION", True):
                error = "Please verify your email address before logging in."
            else:
                login_rate_success(email)
                if password_needs_rehash(user.password_hash):
                    user.password_hash = password_hash(password)
                user.last_login_at = datetime.now()
                log_activity(user.id, "auth_login", "user", user.id)
                db.session.commit()
                establish_session(user)
                from services.auth_service import admin_mfa_needed
                if user.role == "admin":
                    session["admin_mfa_user_id"] = int(user.id)
                    session["admin_mfa_verified_at"] = int(time.time())
                    session["admin_reauth_user_id"] = int(user.id)
                    session["admin_reauth_at"] = int(time.time())
                    if admin_mfa_needed(user):
                        return redirect("/admin/mfa.php", code=303)
                flash(f"Welcome back, {user.name or 'user'}!", "success")
                return redirect(dashboard_for(user.role), code=303)
    return render_template("auth/login.html", page_title="Login — LocalConnect", error=error)


@bp.route("/login.php", methods=["GET"])
def login_legacy():
    return redirect("/auth/login.php", code=302)


@bp.route("/auth/register.php", methods=["GET", "POST"])
@require_guest
def register():
    role = _registration_role()
    errors: list[str] = []
    if request.method == "POST":
        try:
            name = clean_text(request.form.get("name"), 120, True, "Full name")
            email = normalize_email(request.form.get("email"))
            phone = clean_text(request.form.get("phone"), 25, False, "Phone")
            city = clean_text(request.form.get("city"), 100, False, "City")
            state = clean_text(request.form.get("state"), 100, False, "State")
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if password != confirm:
                raise ValueError("Passwords do not match.")
            user = register_user(name=name, email=email, phone=phone, password=password, role=role, city=city, state=state)
        except ValueError as exc:
            errors.append(str(exc))
        except SQLAlchemyError:
            db.session.rollback()
            security_log("registration_failed")
            errors.append("We could not create your account right now. Please try again.")
        else:
            if current_app.config.get("APP_REQUIRE_EMAIL_VERIFICATION", True):
                token = create_auth_token(user.id, "email_verify", 86400)
                link = absolute_url(f"auth/verify-email.php?selector={token['selector']}&token={token['token']}")
                sent = send_app_email(user.email, "Verify your LocalConnect email", f"Open this link to verify your account:\n{link}\n\nThis link expires in 24 hours.")
                flash("Account created. Check your email to verify it before logging in." if sent else "Account created, but verification email delivery is not configured. Contact the administrator.", "success")
                return redirect("/auth/login.php", code=303)
            establish_session(user)
            flash("Welcome to LocalConnect! Your account has been created.", "success")
            return redirect(dashboard_for(user.role), code=303)
    return render_template("auth/register.html", page_title="Create account — LocalConnect", errors=errors, role=role)


@bp.route("/register.php", methods=["GET"])
def register_legacy():
    query = f"?role={request.args['role']}" if request.args.get("role") else ""
    return redirect("/auth/register.php" + query, code=302)


def _perform_logout():
    user = current_user()
    if user:
        log_activity(user.id, "auth_logout", "user", user.id)
        db.session.commit()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/auth/login.php", code=303)


@bp.route("/auth/logout.php", methods=["POST"])
@require_login
def logout():
    return _perform_logout()


@bp.route("/logout.php", methods=["POST"])
@require_login
def logout_legacy():
    return _perform_logout()


@bp.route("/auth/forgot-password.php", methods=["GET", "POST"])
@require_guest
def forgot_password():
    message = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        retry = rate_check("password-reset", email)
        if retry <= 0:
            rate_hit("password-reset", email, 3, 900, 900)
            if is_valid_email(email):
                user = db.session.scalar(select(User).where(User.email == email, User.status != "blocked").limit(1))
                if user:
                    token = create_auth_token(user.id, "password_reset", 3600)
                    link = absolute_url(f"auth/reset-password.php?selector={token['selector']}&token={token['token']}")
                    send_app_email(user.email, "Reset your LocalConnect password", f"Open this link to reset your password:\n{link}\n\nThis link expires in 1 hour.")
        else:
            security_log("password_reset_rate_limited", retry_after=retry)
        message = "If that email belongs to an eligible account, password-reset instructions will be sent."
    return render_template("auth/forgot_password.html", page_title="Forgot password — LocalConnect", message=message)


@bp.route("/auth/reset-password.php", methods=["GET", "POST"])
@require_guest
def reset_password():
    selector = request.form.get("selector") or request.args.get("selector") or ""
    token = request.form.get("token") or request.args.get("token") or ""
    record = find_valid_auth_token("password_reset", selector, token) if request.method == "GET" else None
    error = ""
    if request.method == "POST":
        record = find_valid_auth_token("password_reset", selector, token, lock=True)
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not record:
            error = "This reset link is invalid or expired."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                validate_new_password(password)
                user = db.session.get(User, record.user_id)
                if not user:
                    raise ValueError("User not found")
                user.password_hash = password_hash(password)
                user.session_version = int(user.session_version or 1) + 1
                record.used_at = datetime.now()
                db.session.execute(delete(AuthToken).where(AuthToken.user_id == user.id, AuthToken.purpose == "password_reset", AuthToken.used_at.is_(None)))
                log_activity(user.id, "password_reset_completed", "user", user.id)
                db.session.commit()
                flash("Password updated. You can now login.", "success")
                return redirect("/auth/login.php", code=303)
            except ValueError as exc:
                db.session.rollback()
                error = str(exc) if str(exc) != "User not found" else "Could not reset the password. Please request a new link."
            except Exception:
                db.session.rollback()
                error = "Could not reset the password. Please request a new link."
    return render_template("auth/reset_password.html", page_title="Choose new password — LocalConnect", error=error, record=record, selector=selector, token=token)


@bp.route("/auth/resend-verification.php", methods=["GET", "POST"])
@require_guest
def resend_verification():
    message = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        retry = rate_check("email-verification", email)
        if retry <= 0:
            rate_hit("email-verification", email, 3, 900, 900)
            if is_valid_email(email):
                user = db.session.scalar(select(User).where(User.email == email, User.status != "blocked").limit(1))
                if user and not user.email_verified_at:
                    token = create_auth_token(user.id, "email_verify", 86400)
                    link = absolute_url(f"auth/verify-email.php?selector={token['selector']}&token={token['token']}")
                    send_app_email(user.email, "Verify your LocalConnect email", f"Open this link to verify your account:\n{link}\n\nThis link expires in 24 hours.")
        else:
            security_log("verification_rate_limited", retry_after=retry)
        message = "If the account needs verification, a new verification message will be sent."
    return render_template("auth/resend_verification.html", page_title="Resend verification — LocalConnect", message=message)


@bp.route("/auth/verify-email.php", methods=["GET"])
def verify_email():
    selector = request.args.get("selector", "")
    token = request.args.get("token", "")
    record = find_valid_auth_token("email_verify", selector, token, lock=True)
    if not record:
        flash("This verification link is invalid or expired.", "error")
        return redirect("/auth/login.php", code=303)
    try:
        user = db.session.get(User, record.user_id)
        if not user:
            raise ValueError("User not found")
        if not user.email_verified_at:
            user.email_verified_at = datetime.now()
        if user.status == "pending":
            user.status = "active"
        record.used_at = datetime.now()
        log_activity(user.id, "email_verified", "user", user.id)
        db.session.commit()
        flash("Email verified. You can now login.", "success")
    except Exception:
        db.session.rollback()
        flash("Email verification could not be completed.", "error")
    return redirect("/auth/login.php", code=303)
