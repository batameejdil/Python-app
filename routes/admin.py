from __future__ import annotations

import secrets
import time
from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from extensions import db
from models.security import AdminMfa
from services.auth_service import (
    admin_mfa_record,
    base32_encode_secret,
    decrypt_sensitive,
    encrypt_sensitive,
    log_activity,
    mfa_secret_from_record,
    otpauth_uri,
    password_verify,
    safe_admin_return,
    security_log,
    verify_totp,
)
from utils.auth import admin_mfa_verified, current_user, require_roles

bp = Blueprint("admin", __name__)


@bp.get("/admin")
@bp.get("/admin/")
def admin_root():
    return redirect("/admin/index.php", code=302)


@bp.get("/admin/login.php")
def admin_login_redirect():
    return redirect("/auth/login.php", code=302)


@bp.route("/admin/mfa.php", methods=["GET", "POST"])
@require_roles("admin")
def mfa():
    user = current_user()
    assert user is not None
    uid = int(user.id)
    record = admin_mfa_record(uid)
    error = ""
    if request.method == "POST":
        action = request.form.get("action", "verify")
        try:
            if action == "verify":
                if not record:
                    raise ValueError("MFA is not configured yet.")
                step = verify_totp(mfa_secret_from_record(record), request.form.get("code", "").strip(), record.last_used_step)
                if step is None:
                    raise ValueError("Invalid or already-used authentication code.")
                record.last_used_step = step
                record.last_verified_at = datetime.now()
                session["admin_mfa_user_id"] = uid
                session["admin_mfa_verified_at"] = int(time.time())
                log_activity(uid, "admin_mfa_verified", "user", uid)
                db.session.commit()
                return redirect("/admin/index.php", code=303)
            if action == "enable":
                if record:
                    raise ValueError("MFA is already enabled.")
                if not password_verify(request.form.get("password", ""), user.password_hash):
                    raise ValueError("Password confirmation failed.")
                pending = session.get("pending_mfa_secret_box")
                if not isinstance(pending, dict):
                    raise ValueError("MFA setup session expired. Reload this page.")
                try:
                    secret = decrypt_sensitive(str(pending["ciphertext"]), str(pending["nonce"]), str(pending["alg"]))
                except (KeyError, ValueError, TypeError):
                    raise ValueError("MFA setup session expired. Reload this page.")
                step = verify_totp(secret, request.form.get("code", "").strip())
                if step is None:
                    raise ValueError("The authenticator code is not valid.")
                encrypted = encrypt_sensitive(secret)
                db.session.add(AdminMfa(user_id=uid, secret_ciphertext=encrypted["ciphertext"], secret_nonce=encrypted["nonce"], encryption_alg=encrypted["alg"], enabled_at=datetime.now(), last_used_step=step, last_verified_at=datetime.now()))
                session.pop("pending_mfa_secret_box", None)
                session["admin_mfa_user_id"] = uid
                session["admin_mfa_verified_at"] = int(time.time())
                session["admin_reauth_user_id"] = uid
                session["admin_reauth_at"] = int(time.time())
                log_activity(uid, "admin_mfa_enabled", "user", uid)
                db.session.commit()
                flash("Admin MFA enabled.", "success")
                return redirect("/admin/index.php", code=303)
            if action == "disable":
                if current_app.config.get("APP_ADMIN_MFA_REQUIRED", True):
                    raise ValueError("MFA is required by server policy and cannot be disabled.")
                if not record:
                    raise ValueError("MFA is not enabled.")
                if not password_verify(request.form.get("password", ""), user.password_hash):
                    raise ValueError("Password confirmation failed.")
                step = verify_totp(mfa_secret_from_record(record), request.form.get("code", "").strip(), record.last_used_step)
                if step is None:
                    raise ValueError("Invalid authentication code.")
                db.session.delete(record)
                for key in ("admin_mfa_user_id", "admin_mfa_verified_at", "admin_reauth_user_id", "admin_reauth_at"):
                    session.pop(key, None)
                log_activity(uid, "admin_mfa_disabled", "user", uid)
                db.session.commit()
                flash("Admin MFA disabled.", "success")
                return redirect("/admin/mfa.php", code=303)
            raise ValueError("Unsupported MFA action.")
        except ValueError as exc:
            db.session.rollback()
            error = str(exc)
        except Exception as exc:
            db.session.rollback()
            security_log("admin_mfa_error", user_id=uid, error_class=type(exc).__name__)
            error = "MFA operation failed."
    record = admin_mfa_record(uid)
    secret = None
    uri = None
    if not record:
        pending = session.get("pending_mfa_secret_box")
        if not isinstance(pending, dict):
            secret = base32_encode_secret(secrets.token_bytes(20))
            session["pending_mfa_secret_box"] = encrypt_sensitive(secret)
        else:
            try:
                secret = decrypt_sensitive(str(pending["ciphertext"]), str(pending["nonce"]), str(pending["alg"]))
            except (KeyError, ValueError, TypeError):
                secret = base32_encode_secret(secrets.token_bytes(20))
                session["pending_mfa_secret_box"] = encrypt_sensitive(secret)
        uri = otpauth_uri(secret, user.email)
    return render_template("admin/mfa.html", page_title="Admin MFA — LocalConnect", error=error, record=record, mfa_verified=admin_mfa_verified(user), secret=secret, otpauth=uri)


@bp.route("/admin/reauth.php", methods=["GET", "POST"])
@require_roles("admin")
def reauth():
    user = current_user()
    assert user is not None
    return_path = safe_admin_return(request.args.get("return") or request.form.get("return") or "admin/index.php")
    error = ""
    if request.method == "POST":
        if password_verify(request.form.get("password", ""), user.password_hash):
            session["admin_reauth_user_id"] = int(user.id)
            session["admin_reauth_at"] = int(time.time())
            log_activity(user.id, "admin_reauthenticated", "user", user.id)
            db.session.commit()
            return redirect("/" + return_path, code=303)
        error = "Password confirmation failed."
    return render_template("admin/reauth.html", page_title="Confirm admin access — LocalConnect", error=error, return_path=return_path)

# Phase 5 functional administration routes.
from decimal import Decimal
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from models.billing import (
    Advertisement, ManualPaymentSubmission, Payment, PaymentMethod, PaymentMethodAudit,
    PaymentStatusHistory, PaymentWebhookEvent, Subscription, SubscriptionPlan,
)
from models.core import Category, PlatformActivity, User
from models.marketplace import BusinessProfile, ProviderProfile, Report, Review, Service, ServiceRequest
from services.billing_service import (
    SUPPORTED_GATEWAYS, gateway_config_status, normalize_currency, payment_method_config_status,
    payment_method_snapshot, reconcile_razorpay, record_method_audit, valid_upi_id,
    verify_manual_payment,
)
from services.marketplace_service import datetime_or_none, decimal_or_none, page_window, slugify, validated_http_url
from utils.auth import require_admin_mfa_for_sensitive, require_recent_admin_reauth


@bp.get("/admin/index.php")
@require_roles("admin")
def dashboard():
    stats = {
        "users": int(db.session.scalar(select(func.count(User.id))) or 0),
        "customers": int(db.session.scalar(select(func.count(User.id)).where(User.role == "customer")) or 0),
        "providers": int(db.session.scalar(select(func.count(User.id)).where(User.role == "provider")) or 0),
        "businesses": int(db.session.scalar(select(func.count(User.id)).where(User.role == "business")) or 0),
        "verified": int((db.session.scalar(select(func.count(ProviderProfile.id)).where(ProviderProfile.verification_status == "verified")) or 0) + (db.session.scalar(select(func.count(BusinessProfile.id)).where(BusinessProfile.verification_status == "verified")) or 0)),
        "requests": int(db.session.scalar(select(func.count(ServiceRequest.id))) or 0),
        "completed": int(db.session.scalar(select(func.count(ServiceRequest.id)).where(ServiceRequest.status == "completed")) or 0),
        "pending": int(db.session.scalar(select(func.count(ServiceRequest.id)).where(ServiceRequest.status == "pending")) or 0),
        "reviews": int(db.session.scalar(select(func.count(Review.id)).where(Review.status == "published")) or 0),
        "revenue": db.session.scalar(select(func.coalesce(func.sum(Payment.amount), 0)).where(Payment.status == "paid")) or Decimal("0"),
    }
    recent = db.session.execute(select(PlatformActivity.id, PlatformActivity.action, PlatformActivity.target_type, PlatformActivity.target_id, PlatformActivity.details, PlatformActivity.created_at, User.name.label("actor_name")).outerjoin(User, User.id == PlatformActivity.actor_id).order_by(PlatformActivity.id.desc()).limit(20)).mappings().all()
    return render_template("admin/dashboard.html", page_title="Admin Dashboard — LocalConnect", stats=stats, recent=recent)


@bp.route("/admin/users.php", methods=["GET", "POST"])
@require_roles("admin")
def users():
    admin = current_user(); assert admin is not None
    if request.method == "POST":
        try: user_id = int(request.form.get("id", 0))
        except ValueError: user_id = 0
        action = request.form.get("action", "")
        if user_id == admin.id:
            flash("You cannot block your own admin account.", "error")
        elif action in {"block", "unblock"}:
            target = db.session.scalar(select(User).where(User.id == user_id, User.role != "admin").limit(1))
            if target:
                target.status = "blocked" if action == "block" else "active"; target.session_version = int(target.session_version or 1) + 1
                log_activity(admin.id, f"user_{action}", "user", target.id); db.session.commit(); flash("User status updated.", "success")
        return redirect("/admin/users.php", code=303)
    role = request.args.get("role", "") if request.args.get("role", "") in {"customer", "provider", "business", "admin"} else ""
    page, per, offset = page_window(30, 60); stmt = select(User)
    if role: stmt = stmt.where(User.role == role)
    rows = db.session.scalars(stmt.order_by(User.id.desc()).limit(per + 1).offset(offset)).all(); has_next = len(rows) > per; rows = rows[:per]
    return render_template("admin/users.html", page_title="Manage Users — LocalConnect", rows=rows, role=role, page=page, has_next=has_next)


@bp.route("/admin/providers.php", methods=["GET", "POST"])
@require_roles("admin")
def providers():
    admin = current_user(); assert admin is not None
    if request.method == "POST":
        try: user_id = int(request.form.get("user_id", 0))
        except ValueError: user_id = 0
        status = request.form.get("status", "")
        if status in {"pending", "verified", "rejected"}:
            profile = db.session.scalar(select(ProviderProfile).where(ProviderProfile.user_id == user_id).limit(1))
            if profile:
                profile.verification_status = status; profile.verified_at = datetime.now() if status == "verified" else None; log_activity(admin.id, f"verification_{status}", "provider", user_id); db.session.commit(); flash("Verification status updated.", "success")
        return redirect("/admin/providers.php", code=303)
    page, per, offset = page_window(30, 60)
    rows = db.session.execute(select(User.id, User.name, User.email, User.status, ProviderProfile.verification_status, ProviderProfile.created_at).join(ProviderProfile, ProviderProfile.user_id == User.id).where(User.role == "provider").order_by(ProviderProfile.id.desc()).limit(per + 1).offset(offset)).mappings().all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/providers.html", page_title="Manage Providers — LocalConnect", rows=rows, page=page, has_next=has_next)


@bp.route("/admin/businesses.php", methods=["GET", "POST"])
@require_roles("admin")
def businesses():
    admin=current_user(); assert admin is not None
    if request.method == "POST":
        try: user_id=int(request.form.get("user_id",0))
        except ValueError: user_id=0
        status=request.form.get("status","")
        if status in {"pending","verified","rejected"}:
            profile=db.session.scalar(select(BusinessProfile).where(BusinessProfile.user_id==user_id).limit(1))
            if profile:
                profile.verification_status=status; profile.verified_at=datetime.now() if status=="verified" else None; log_activity(admin.id,f"verification_{status}","business",user_id); db.session.commit(); flash("Verification status updated.","success")
        return redirect("/admin/businesses.php",code=303)
    page,per,offset=page_window(30,60)
    rows=db.session.execute(select(User.id,User.name,User.email,User.status,func.coalesce(func.nullif(BusinessProfile.business_name,""),User.name).label("display_name"),BusinessProfile.verification_status,BusinessProfile.created_at).join(BusinessProfile,BusinessProfile.user_id==User.id).where(User.role=="business").order_by(BusinessProfile.id.desc()).limit(per+1).offset(offset)).mappings().all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/businesses.html",page_title="Manage Businesses — LocalConnect",rows=rows,page=page,has_next=has_next)


@bp.route("/admin/categories.php", methods=["GET", "POST"])
@require_roles("admin")
def categories():
    admin=current_user(); assert admin is not None
    if request.method=="POST":
        action=request.form.get("action","save")
        try: category_id=int(request.form.get("id",0))
        except ValueError: category_id=0
        try:
            if action=="delete":
                row=db.session.get(Category,category_id)
                if row: db.session.delete(row); db.session.commit(); flash("Category deleted.","success")
            else:
                name=clean_text(request.form.get("name",""),120,True,"Category name"); icon=clean_text(request.form.get("icon","fa-tag"),80,False,"Icon")
                if icon and not __import__('re').fullmatch(r"[a-z0-9-]+",icon,__import__('re').I): raise ValueError("Category name or icon is invalid.")
                row=db.session.get(Category,category_id) if category_id else Category()
                row.name=name; row.slug=slugify(name); row.icon=icon or None; row.is_active=1 if not category_id or request.form.get("is_active") else 0
                if not category_id: db.session.add(row)
                db.session.flush(); log_activity(admin.id,"category_saved","category",row.id,name); db.session.commit(); flash("Category saved.","success")
        except IntegrityError:
            db.session.rollback(); flash("Category is in use, duplicated, or cannot be changed.","error")
        except ValueError as exc:
            db.session.rollback(); flash(str(exc),"error")
        return redirect("/admin/categories.php",code=303)
    rows=db.session.scalars(select(Category).order_by(Category.name)).all()
    return render_template("admin/categories.html",page_title="Categories — Admin",rows=rows)


@bp.route("/admin/services.php", methods=["GET", "POST"])
@require_roles("admin")
def services():
    admin=current_user(); assert admin is not None
    if request.method=="POST":
        try: service_id=int(request.form.get("id",0))
        except ValueError: service_id=0
        row=db.session.get(Service,service_id)
        if row:
            row.is_active=0 if row.is_active else 1; log_activity(admin.id,"service_toggled","service",row.id); db.session.commit()
        return redirect("/admin/services.php",code=303)
    page,per,offset=page_window(40,80)
    rows=db.session.execute(select(Service.id,Service.name,Service.is_active,Category.name.label("category")).join(Category,Category.id==Service.category_id).order_by(Category.name,Service.name,Service.id).limit(per+1).offset(offset)).mappings().all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/services.html",page_title="Services — Admin",rows=rows,page=page,has_next=has_next)


@bp.get("/admin/requests.php")
@require_roles("admin")
def requests_ledger():
    rows=db.session.execute(select(ServiceRequest.id,ServiceRequest.title,ServiceRequest.status,ServiceRequest.created_at,User.name.label("customer"),Category.name.label("category")).join(User,User.id==ServiceRequest.customer_id).join(Category,Category.id==ServiceRequest.category_id).order_by(ServiceRequest.id.desc()).limit(200)).mappings().all()
    return render_template("admin/requests.html",page_title="Requests — Admin",rows=rows)


@bp.route("/admin/reviews.php", methods=["GET", "POST"])
@require_roles("admin")
def reviews_admin():
    admin=current_user(); assert admin is not None
    if request.method=="POST":
        try: review_id=int(request.form.get("id",0))
        except ValueError: review_id=0
        status=request.form.get("status","")
        if status in {"published","hidden","removed"}:
            row=db.session.get(Review,review_id)
            if row: row.status=status; log_activity(admin.id,f"review_{status}","review",review_id); db.session.commit()
        return redirect("/admin/reviews.php",code=303)
    page,per,offset=page_window(30,60); customer=User.__table__.alias("customer"); target=User.__table__.alias("target")
    rows=db.session.execute(select(Review.id,Review.request_id,Review.rating,Review.comment,Review.status,Review.created_at,customer.c.name.label("customer"),target.c.name.label("target")).join(customer,customer.c.id==Review.customer_id).join(target,target.c.id==Review.target_user_id).order_by(Review.id.desc()).limit(per+1).offset(offset)).mappings().all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/reviews.html",page_title="Reviews — Admin",rows=rows,page=page,has_next=has_next)


@bp.route("/admin/reports.php", methods=["GET", "POST"])
@require_roles("admin")
def reports_admin():
    admin=current_user(); assert admin is not None
    if request.method=="POST":
        try:
            report_id=int(request.form.get("id",0)); status=request.form.get("status",""); note=clean_text(request.form.get("note",""),500,False,"Moderation note")
            if status not in {"open","investigating","resolved","dismissed"}: raise ValueError("Invalid report status.")
            row=db.session.get(Report,report_id)
            if row:
                row.status=status; row.resolved_by=admin.id if status in {"resolved","dismissed"} else None; row.resolution_note=note or None; log_activity(admin.id,f"report_{status}","report",report_id,note); db.session.commit()
        except (ValueError,TypeError) as exc:
            db.session.rollback(); flash(str(exc),"error")
        return redirect("/admin/reports.php",code=303)
    page,per,offset=page_window(20,50)
    rows=db.session.execute(select(Report.id,Report.target_type,Report.target_id,Report.reason,Report.details,Report.status,Report.resolution_note,Report.created_at,User.name.label("reporter")).join(User,User.id==Report.reporter_id).order_by(Report.id.desc()).limit(per+1).offset(offset)).mappings().all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/reports.html",page_title="Reports — Admin",rows=rows,page=page,has_next=has_next)


@bp.route("/admin/advertisements.php", methods=["GET", "POST"])
@require_roles("admin")
def advertisements():
    admin=current_user(); assert admin is not None
    if request.method=="POST":
        try:
            title=clean_text(request.form.get("title",""),180,True,"Advertisement title"); description=clean_text(request.form.get("description",""),500,False,"Description")
            target_url=validated_http_url(request.form.get("target_url",""),255); placement=clean_text(request.form.get("placement","homepage"),80,True,"Placement")
            if not __import__('re').fullmatch(r"[a-z0-9_-]+",placement,__import__('re').I): raise ValueError("Placement is invalid.")
            status=request.form.get("status","draft")
            if status not in {"draft","active","paused","expired"}: raise ValueError("Advertisement status is invalid.")
            starts=datetime_or_none(request.form.get("starts_at"),"Start date/time"); ends=datetime_or_none(request.form.get("ends_at"),"End date/time")
            if starts and ends and ends<starts: raise ValueError("End date/time must be after the start.")
            budget=decimal_or_none(request.form.get("budget",0),"Budget") or Decimal("0")
            row=Advertisement(title=title,description=description or None,target_url=target_url,placement=placement,status=status,starts_at=starts,ends_at=ends,created_by=admin.id,budget=budget)
            db.session.add(row); db.session.flush(); log_activity(admin.id,"advertisement_created","advertisement",row.id,title); db.session.commit(); flash("Advertisement created.","success")
        except (ValueError,TypeError) as exc: db.session.rollback(); flash(str(exc),"error")
        return redirect("/admin/advertisements.php",code=303)
    page,per,offset=page_window(30,60); rows=db.session.scalars(select(Advertisement).order_by(Advertisement.id.desc()).limit(per+1).offset(offset)).all(); has_next=len(rows)>per; rows=rows[:per]
    return render_template("admin/advertisements.html",page_title="Advertisements — Admin",rows=rows,page=page,has_next=has_next)


@bp.get("/admin/subscriptions.php")
@require_roles("admin")
def subscriptions_admin():
    statuses={"active","scheduled","expired","cancelled","pending","suspended"}; status=request.args.get("status",""); status=status if status in statuses else ""; plan=(request.args.get("plan") or "").strip()[:40]; qtext=(request.args.get("q") or "").strip()[:120]
    page,per,offset=page_window(25,25); stmt=select(Subscription,User).join(User,User.id==Subscription.user_id)
    if status: stmt=stmt.where(Subscription.status==status)
    if plan: stmt=stmt.where(Subscription.plan==plan)
    if qtext:
        like=f"%{qtext}%"; stmt=stmt.where(or_(User.email.like(like),User.name.like(like),Subscription.invoice_reference.like(like)))
    total=int(db.session.scalar(select(func.count()).select_from(stmt.subquery())) or 0); pairs=db.session.execute(stmt.order_by(Subscription.id.desc()).limit(per).offset(offset)).all(); plans=db.session.scalars(select(SubscriptionPlan).order_by(SubscriptionPlan.price_monthly,SubscriptionPlan.id)).all()
    return render_template("admin/subscriptions.html",page_title="Subscriptions — Admin",rows=pairs,plans=plans,total=total,page=page,per=per,filters={"status":status,"plan":plan,"q":qtext})


@bp.get("/admin/payments.php")
@require_roles("admin")
def payments_admin():
    statuses={"pending","paid","failed","cancelled","refunded","partially_refunded","disputed","requires_review"}; recons={"pending","matched","warning","manual_review"}
    status=request.args.get("status",""); status=status if status in statuses else ""; recon=request.args.get("reconciliation",""); recon=recon if recon in recons else ""; qtext=(request.args.get("q") or "").strip()[:120]
    page,per,offset=page_window(25,25); stmt=select(Payment,User,PaymentMethod.name.label("current_method_name")).join(User,User.id==Payment.user_id).outerjoin(PaymentMethod,PaymentMethod.id==Payment.payment_method_id)
    if status: stmt=stmt.where(Payment.status==status)
    if recon: stmt=stmt.where(Payment.reconciliation_status==recon)
    if qtext:
        like=f"%{qtext}%"; stmt=stmt.where(or_(User.email.like(like),User.name.like(like),Payment.provider_order_id.like(like),Payment.provider_payment_id.like(like),Payment.invoice_reference.like(like)))
    total=int(db.session.scalar(select(func.count()).select_from(stmt.subquery())) or 0); rows=db.session.execute(stmt.order_by(Payment.id.desc()).limit(per).offset(offset)).all()
    return render_template("admin/payments.html",page_title="Payments — Admin",rows=rows,total=total,page=page,per=per,filters={"status":status,"reconciliation":recon,"q":qtext})


@bp.route("/admin/payment-detail.php", methods=["GET", "POST"])
@require_roles("admin")
def payment_detail():
    admin=current_user(); assert admin is not None
    try: payment_id=int(request.args.get("id") or request.form.get("id") or 0)
    except ValueError: payment_id=0
    if payment_id<=0: abort(404)
    error=""
    if request.method=="POST":
        gate=require_admin_mfa_for_sensitive()
        if gate: return gate
        gate=require_recent_admin_reauth(f"admin/payment-detail.php?id={payment_id}",600)
        if gate: return gate
        try:
            action=request.form.get("action","")
            if action=="reconcile_gateway": reconcile_razorpay(payment_id,"reconciliation",actor_id=admin.id); log_activity(admin.id,"payment_gateway_reconciled","payment",payment_id,"Server-side gateway reconciliation completed."); flash("Gateway payment reconciled.","success")
            elif action=="approve_manual": verify_manual_payment(payment_id,admin.id,True,request.form.get("review_note","")); flash("Manual payment verified and entitlement processed.","success")
            elif action=="reject_manual": verify_manual_payment(payment_id,admin.id,False,request.form.get("review_note","")); flash("Manual payment submission rejected.","success")
            else: raise ValueError("Unsupported payment action.")
            return redirect(f"/admin/payment-detail.php?id={payment_id}",code=303)
        except Exception as exc:
            db.session.rollback(); error=str(exc) if isinstance(exc,(ValueError,RuntimeError)) else "Payment action failed."; security_log("admin_payment_action_failed",admin_id=admin.id,payment_id=payment_id,error_class=type(exc).__name__)
    payment=db.session.get(Payment,payment_id)
    if not payment: abort(404)
    owner=db.session.get(User,payment.user_id); method=db.session.get(PaymentMethod,payment.payment_method_id) if payment.payment_method_id else None
    manual=db.session.scalar(select(ManualPaymentSubmission).where(ManualPaymentSubmission.payment_id==payment_id).limit(1)); history=db.session.execute(select(PaymentStatusHistory,User.name.label("actor_name")).outerjoin(User,User.id==PaymentStatusHistory.actor_user_id).where(PaymentStatusHistory.payment_id==payment_id).order_by(PaymentStatusHistory.id.desc()).limit(100)).all(); events=db.session.scalars(select(PaymentWebhookEvent).where(or_(PaymentWebhookEvent.provider_payment_id==payment.provider_payment_id,PaymentWebhookEvent.provider_order_id==payment.provider_order_id)).order_by(PaymentWebhookEvent.id.desc()).limit(100)).all()
    return render_template("admin/payment_detail.html",page_title=f"Payment #{payment_id} — Admin",payment=payment,owner=owner,method=method,manual=manual,history=history,events=events,error=error)


@bp.get("/admin/payment-methods.php")
@require_roles("admin")
def payment_methods():
    rows=db.session.scalars(select(PaymentMethod).order_by(PaymentMethod.display_order,PaymentMethod.id)).all(); audit=db.session.execute(select(PaymentMethodAudit,User.name.label("admin_name"),PaymentMethod.name.label("method_name")).join(User,User.id==PaymentMethodAudit.admin_user_id).join(PaymentMethod,PaymentMethod.id==PaymentMethodAudit.payment_method_id).order_by(PaymentMethodAudit.id.desc()).limit(50)).all(); statuses={r.id:payment_method_config_status(r) for r in rows}
    return render_template("admin/payment_methods.html",page_title="Payment Methods — Admin",rows=rows,audit=audit,statuses=statuses)


@bp.route("/admin/payment-method-edit.php", methods=["GET", "POST"])
@require_roles("admin")
def payment_method_edit():
    admin=current_user(); assert admin is not None
    gate=require_admin_mfa_for_sensitive()
    if gate: return gate
    try: method_id=max(0,int(request.args.get("id") or request.form.get("id") or 0))
    except ValueError: method_id=0
    gate=require_recent_admin_reauth("admin/payment-method-edit.php"+(f"?id={method_id}" if method_id else ""),600)
    if gate: return gate
    method=db.session.get(PaymentMethod,method_id) if method_id else None
    if method_id and not method: abort(404)
    error=""
    if request.method=="POST":
        try:
            name=clean_text(request.form.get("name",""),120,True,"Method name"); kind=clean_text(request.form.get("method_type",""),30,True,"Method type")
            if kind not in {"gateway","upi","bank_transfer"}: raise ValueError("Unsupported payment method type.")
            audience=clean_text(request.form.get("audience",""),20,True,"Audience")
            if audience not in {"provider","business","both"}: raise ValueError("Invalid audience.")
            currency=normalize_currency(request.form.get("currency","INR")); order=int(request.form.get("display_order",100))
            if order<0 or order>10000: raise ValueError("Display order must be between 0 and 10000.")
            instructions=clean_text(request.form.get("display_instructions",""),2000,False,"Display instructions"); gateway=None; upi=None; beneficiary=None; reference=None
            if kind=="gateway":
                gateway=clean_text(request.form.get("gateway_code",""),60,True,"Gateway")
                if gateway not in SUPPORTED_GATEWAYS: raise ValueError("Unsupported gateway.")
            elif kind=="upi":
                upi=clean_text(request.form.get("merchant_upi_id",""),190,True,"Merchant UPI ID")
                if not valid_upi_id(upi): raise ValueError("Merchant UPI ID format is invalid.")
                if not instructions: raise ValueError("UPI display instructions are required.")
            else:
                beneficiary=clean_text(request.form.get("bank_beneficiary",""),160,True,"Bank beneficiary"); reference=clean_text(request.form.get("bank_reference",""),190,False,"Bank reference")
                if not instructions: raise ValueError("Bank transfer display instructions are required.")
            active=1 if request.form.get("is_active") else 0; posted={"method_type":kind,"gateway_code":gateway,"merchant_upi_id":upi,"bank_beneficiary":beneficiary,"display_instructions":instructions}
            if active and not payment_method_config_status(posted)["configured"]: raise ValueError("This method cannot be activated until its required configuration is complete.")
            if method:
                before=payment_method_snapshot(method); old_active=int(method.is_active or 0); old_order=int(method.display_order or 0)
                method.name=name; method.method_type=kind; method.gateway_code=gateway; method.audience=audience; method.currency=currency; method.merchant_upi_id=upi; method.bank_beneficiary=beneficiary; method.bank_reference=reference or None; method.display_instructions=instructions or None; method.display_order=order; method.is_active=active; method.updated_by=admin.id; db.session.flush(); action="activate" if old_active!=active and active else ("deactivate" if old_active!=active else ("reorder" if old_order!=order else "update")); record_method_audit(method.id,admin.id,action,before,payment_method_snapshot(method)); log_activity(admin.id,f"payment_method_{action}","payment_method",method.id,f"code={method.code}")
            else:
                code=slugify(clean_text(request.form.get("code",""),60,True,"Method code"))[:60]
                if not __import__('re').fullmatch(r"[a-z0-9][a-z0-9-]{1,59}",code): raise ValueError("Method code must contain letters, numbers or hyphens.")
                method=PaymentMethod(code=code,name=name,method_type=kind,gateway_code=gateway,audience=audience,currency=currency,merchant_upi_id=upi,bank_beneficiary=beneficiary,bank_reference=reference or None,display_instructions=instructions or None,display_order=order,is_active=active,created_by=admin.id,updated_by=admin.id); db.session.add(method); db.session.flush(); record_method_audit(method.id,admin.id,"create",None,payment_method_snapshot(method)); log_activity(admin.id,"payment_method_create","payment_method",method.id,f"code={code}")
            db.session.commit(); flash("Payment method saved.","success"); return redirect("/admin/payment-methods.php",code=303)
        except IntegrityError: db.session.rollback(); error="Payment method code already exists."
        except (ValueError,TypeError) as exc: db.session.rollback(); error=str(exc)
        except Exception as exc: db.session.rollback(); security_log("payment_method_admin_error",admin_id=admin.id,error_class=type(exc).__name__); error="Payment method could not be saved."
    defaults={"code":"","name":"","method_type":"gateway","gateway_code":"razorpay","audience":"both","currency":"INR","merchant_upi_id":"","bank_beneficiary":"","bank_reference":"","display_instructions":"","display_order":100,"is_active":0}
    if method:
        form={key:getattr(method,key,defaults[key]) for key in defaults}
    else:
        form=dict(defaults)
    if request.method=="POST":
        for key in defaults:
            if key=="is_active": form[key]=1 if request.form.get("is_active") else 0
            elif key in request.form: form[key]=request.form.get(key,"")
    gateway_statuses={}
    for code,required in SUPPORTED_GATEWAYS.items():
        status=gateway_config_status(code)
        status={**status,"label":code.title(),"indicators":{name:("set" if str(current_app.config.get(name,"") or "").strip() and "REPLACE_WITH_" not in str(current_app.config.get(name,"") or "") else "missing") for name in required}}
        gateway_statuses[code]=status
    return render_template("admin/payment_method_edit.html",page_title=("Edit" if method else "Add")+" Payment Method — Admin",method=method,form=form,error=error,gateway_statuses=gateway_statuses)
