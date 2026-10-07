from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_from_directory
from sqlalchemy import func, literal, or_, select, update
from sqlalchemy.exc import IntegrityError

from extensions import db
from models.core import Category, User
from models.marketplace import (
    BusinessProfile, Favorite, Notification, PortfolioImage, ProviderProfile, ProviderService,
    Report, RequestStatusHistory, Review, Service, ServiceRequest,
)
from services.auth_service import clean_text, is_valid_email
from services.marketplace_service import create_notification, is_favorite, page_window, rating_summary
from services.storage_service import resolve_managed_upload, upload_storage_root
from utils.auth import current_user, require_login

bp = Blueprint("main", __name__)


@bp.get("/uploads/<path:filename>")
def uploaded_file(filename: str):
    # Public user images keep the legacy URL while bytes can live on a persistent disk.
    managed = resolve_managed_upload(f"uploads/{filename}")
    if managed is None or not managed.is_file():
        abort(404)
    relative = managed.relative_to(upload_storage_root()).as_posix()
    response = send_from_directory(upload_storage_root(), relative, conditional=True)
    ttl = int(current_app.config.get("UPLOAD_PUBLIC_CACHE_SECONDS", 86400))
    response.headers["Cache-Control"] = f"public, max-age={ttl}, immutable"
    response.headers["CDN-Cache-Control"] = f"public, max-age={ttl}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.get("/")
@bp.get("/index.php")
def index():
    try:
        categories = db.session.scalars(select(Category).where(Category.is_active == 1).order_by(Category.id).limit(12)).all()
    except Exception:
        db.session.rollback()
        categories = []

    try:
        avg_rating = func.coalesce(func.avg(Review.rating), 0).label("avg_rating")
        review_count = func.count(func.distinct(Review.id)).label("review_count")
        featured = db.session.execute(
            select(User.id, User.name, User.profile_image, User.city, User.area, ProviderProfile.headline,
                   ProviderProfile.price_min, ProviderProfile.price_max, ProviderProfile.verification_status,
                   avg_rating, review_count)
            .join(ProviderProfile, ProviderProfile.user_id == User.id)
            .outerjoin(Review, (Review.target_user_id == User.id) & (Review.status == "published"))
            .where(User.status == "active", User.role == "provider", ProviderProfile.is_featured == 1)
            .group_by(User.id, ProviderProfile.id).order_by(avg_rating.desc(), ProviderProfile.updated_at.desc()).limit(6)
        ).mappings().all()
    except Exception:
        db.session.rollback()
        featured = []

    try:
        businesses = db.session.execute(
            select(User.id, User.name, User.city, User.area, BusinessProfile.business_name, BusinessProfile.logo,
                   BusinessProfile.description, BusinessProfile.verification_status)
            .join(BusinessProfile, BusinessProfile.user_id == User.id)
            .where(User.status == "active", User.role == "business")
            .order_by(BusinessProfile.is_featured.desc(), BusinessProfile.updated_at.desc()).limit(6)
        ).mappings().all()
    except Exception:
        db.session.rollback()
        businesses = []

    return render_template("main/index.html", page_title="LocalConnect — Find Trusted Local Services Near You", categories=categories, featured=featured, businesses=businesses)


@bp.get("/categories.php")
def categories():
    rows = db.session.execute(
        select(Category.id, Category.name, Category.slug, Category.icon, func.count(Service.id).label("service_count"))
        .outerjoin(Service, (Service.category_id == Category.id) & (Service.is_active == 1))
        .where(Category.is_active == 1).group_by(Category.id).order_by(Category.name)
    ).mappings().all()
    return render_template("main/categories.html", page_title="Service Categories — LocalConnect", categories=rows)


@bp.get("/search.php")
def search():
    q = (request.args.get("q") or "").strip()[:180]; location = (request.args.get("location") or "").strip()[:180]
    try: category_id = max(0, int(request.args.get("category", 0)))
    except ValueError: category_id = 0
    role = request.args.get("type", "") if request.args.get("type", "") in {"provider", "business"} else ""
    availability = "available" if request.args.get("availability") == "available" else ""
    sort = request.args.get("sort", "rating") if request.args.get("sort") in {"rating", "reviews", "price", "newest"} else "rating"
    try: max_price = max(0.0, float(request.args.get("max_price", 0) or 0))
    except ValueError: max_price = 0.0
    page, per, offset = page_window(24, 48)
    avg_rating = func.coalesce(func.avg(Review.rating), 0).label("avg_rating"); review_count = func.count(func.distinct(Review.id)).label("review_count")
    stmt = select(User.id, User.name, User.role, User.profile_image, User.city, User.state, User.area,
                  ProviderProfile.headline, ProviderProfile.service_area, ProviderProfile.price_min, ProviderProfile.price_max,
                  ProviderProfile.availability_status, ProviderProfile.verification_status,
                  BusinessProfile.business_name, BusinessProfile.logo, BusinessProfile.description,
                  BusinessProfile.price_min.label("bmin"), BusinessProfile.price_max.label("bmax"), BusinessProfile.verification_status.label("bverify"),
                  avg_rating, review_count).outerjoin(ProviderProfile, ProviderProfile.user_id == User.id).outerjoin(BusinessProfile, BusinessProfile.user_id == User.id).outerjoin(ProviderService, (ProviderService.provider_user_id == User.id) & (ProviderService.is_active == 1)).outerjoin(Service, Service.id == ProviderService.service_id).outerjoin(Review, (Review.target_user_id == User.id) & (Review.status == "published")).where(User.status == "active", User.role.in_(["provider", "business"]))
    if q:
        like = f"%{q}%"; stmt = stmt.where(or_(User.name.like(like), ProviderProfile.headline.like(like), BusinessProfile.business_name.like(like), Service.name.like(like), ProviderService.title.like(like)))
    if location:
        like = f"%{location}%"; stmt = stmt.where(or_(User.city.like(like), User.area.like(like), ProviderProfile.service_area.like(like), BusinessProfile.address.like(like)))
    if category_id: stmt = stmt.where(or_(Service.category_id == category_id, BusinessProfile.category_id == category_id))
    if role: stmt = stmt.where(User.role == role)
    if availability: stmt = stmt.where(or_(User.role == "business", ProviderProfile.availability_status == "available"))
    if max_price > 0:
        stmt = stmt.where(or_((User.role == "provider") & (or_(ProviderProfile.price_min.is_(None), ProviderProfile.price_min <= max_price)), (User.role == "business") & (or_(BusinessProfile.price_min.is_(None), BusinessProfile.price_min <= max_price))))
    stmt = stmt.group_by(User.id, ProviderProfile.id, BusinessProfile.id)
    if sort == "reviews": stmt = stmt.order_by(review_count.desc(), avg_rating.desc(), User.id.desc())
    elif sort == "price": stmt = stmt.order_by(func.coalesce(ProviderProfile.price_min, BusinessProfile.price_min, 999999999).asc(), User.id.desc())
    elif sort == "newest": stmt = stmt.order_by(User.created_at.desc(), User.id.desc())
    else: stmt = stmt.order_by(avg_rating.desc(), review_count.desc(), User.id.desc())
    rows = db.session.execute(stmt.limit(per + 1).offset(offset)).mappings().all(); has_next = len(rows) > per; rows = rows[:per]
    cats = db.session.scalars(select(Category).where(Category.is_active == 1).order_by(Category.name).limit(250)).all()
    return render_template("main/search.html", page_title="Find Local Services — LocalConnect", results=rows, categories=cats, page=page, has_next=has_next, filters={"q":q,"location":location,"category":category_id,"type":role,"availability":availability,"sort":sort,"max_price":max_price})


def _public_profile(user_id: int, role: str):
    user = db.session.scalar(select(User).where(User.id == user_id, User.role == role, User.status == "active").limit(1))
    if not user: abort(404)
    if role == "provider":
        profile = db.session.scalar(select(ProviderProfile).where(ProviderProfile.user_id == user.id).limit(1)); business_category = None
    else:
        profile = db.session.scalar(select(BusinessProfile).where(BusinessProfile.user_id == user.id).limit(1)); business_category = db.session.get(Category, profile.category_id) if profile and profile.category_id else None
    if not profile: abort(404)
    services = db.session.execute(select(ProviderService.id, ProviderService.title, ProviderService.description, ProviderService.price_from, ProviderService.price_to, Service.name, Category.name.label("category")).join(Service, Service.id == ProviderService.service_id).join(Category, Category.id == Service.category_id).where(ProviderService.provider_user_id == user.id, ProviderService.is_active == 1, Service.is_active == 1).order_by(Category.name, Service.name)).mappings().all()
    images = db.session.scalars(select(PortfolioImage).where(PortfolioImage.user_id == user.id).order_by(PortfolioImage.created_at.desc()).limit(12)).all() if role == "provider" else []
    reviews = db.session.execute(select(Review.id, Review.rating, Review.comment, Review.created_at, User.name.label("customer_name")).join(User, User.id == Review.customer_id).where(Review.target_user_id == user.id, Review.status == "published").order_by(Review.created_at.desc()).limit(8)).mappings().all()
    viewer = current_user(); favorite = bool(viewer and viewer.role == "customer" and is_favorite(viewer.id, user.id))
    return user, profile, services, images, reviews, rating_summary(user.id), favorite, business_category


@bp.get("/provider.php")
def provider_detail():
    try: user_id = int(request.args.get("id", 0))
    except ValueError: user_id = 0
    data = _public_profile(user_id, "provider")
    return render_template("main/provider_detail.html", page_title=f"{data[0].name} — Local Service Provider", user=data[0], profile=data[1], services=data[2], images=data[3], reviews=data[4], rating=data[5], favorite=data[6])


@bp.get("/business.php")
def business_detail():
    try: user_id = int(request.args.get("id", 0))
    except ValueError: user_id = 0
    data = _public_profile(user_id, "business")
    name = data[1].business_name or data[0].name
    return render_template("main/business_detail.html", page_title=f"{name} — LocalConnect", user=data[0], profile=data[1], services=data[2], reviews=data[4], rating=data[5], favorite=data[6], category=data[7])


@bp.route("/contact.php", methods=["GET", "POST"])
def contact():
    sent = False; error = ""
    if request.method == "POST":
        try:
            name = clean_text(request.form.get("name", ""), 120, True, "Name"); email = clean_text(request.form.get("email", ""), 190, True, "Email").lower(); message = clean_text(request.form.get("message", ""), 2000, True, "Message")
            if not is_valid_email(email) or len(message) < 10: raise ValueError("Please enter a valid name, email and message.")
            sent = True
        except ValueError as exc: error = str(exc)
    return render_template("main/contact.html", page_title="Contact LocalConnect", sent=sent, error=error)


@bp.route("/notifications.php", methods=["GET", "POST"])
@require_login
def notifications():
    user = current_user(); assert user is not None
    if request.method == "POST":
        if request.form.get("action") == "all":
            db.session.execute(
                update(Notification)
                .where(Notification.user_id == user.id, Notification.is_read == 0)
                .values(is_read=1)
            )
        else:
            try: item_id = int(request.form.get("id", 0))
            except ValueError: item_id = 0
            item = db.session.scalar(select(Notification).where(Notification.id == item_id, Notification.user_id == user.id).limit(1))
            if item: item.is_read = 1
        db.session.commit(); return redirect("/notifications.php", code=303)
    items = db.session.scalars(select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(100)).all()
    return render_template("main/notifications.html", page_title="Notifications — LocalConnect", items=items)


@bp.route("/reviews.php", methods=["GET", "POST"])
@require_login
def reviews():
    user = current_user(); assert user is not None
    if request.method == "POST":
        if user.role != "customer": abort(403)
        try:
            request_id = int(request.form.get("request_id", 0)); rating = int(request.form.get("rating", 0)); comment = clean_text(request.form.get("comment", ""), 2000, False, "Review comment")
            if rating < 1 or rating > 5: raise ValueError("Please choose a rating from 1 to 5 stars.")
            service_request = db.session.scalar(select(ServiceRequest).where(ServiceRequest.id == request_id, ServiceRequest.customer_id == user.id, ServiceRequest.status == "completed").limit(1))
            if not service_request: raise ValueError("You can review only your own completed service request.")
            target = service_request.provider_id or service_request.business_id
            if not target: raise ValueError("This request has no service provider to review.")
            db.session.add(Review(request_id=request_id, customer_id=user.id, target_user_id=target, rating=rating, comment=comment or None, status="published")); create_notification(target, "new_review", "You received a new review", f"A customer left a {rating}-star review.", "reviews.php"); db.session.commit(); flash("Thank you. Your review has been published.", "success")
        except IntegrityError:
            db.session.rollback(); flash("A review for this service request already exists.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback(); flash(str(exc), "error")
        return redirect("/reviews.php", code=303)
    page, per, offset = page_window(20, 40); eligible=[]; mine=[]; received=[]; has_next=False; summary=None
    if user.role == "customer":
        eligible = db.session.execute(select(ServiceRequest.id, ServiceRequest.title, ServiceRequest.updated_at.label("completed_at"), func.coalesce(User.name, "Provider").label("target_name")).outerjoin(Review, Review.request_id == ServiceRequest.id).outerjoin(User, User.id == func.coalesce(ServiceRequest.provider_id, ServiceRequest.business_id)).where(ServiceRequest.customer_id == user.id, ServiceRequest.status == "completed", Review.id.is_(None)).order_by(ServiceRequest.updated_at.desc()).limit(50)).mappings().all()
        mine = db.session.execute(select(Review.id, Review.rating, Review.comment, Review.created_at, ServiceRequest.title, User.name.label("target_name")).join(ServiceRequest, ServiceRequest.id == Review.request_id).join(User, User.id == Review.target_user_id).where(Review.customer_id == user.id).order_by(Review.created_at.desc(), Review.id.desc()).limit(per+1).offset(offset)).mappings().all(); has_next=len(mine)>per; mine=mine[:per]
    elif user.role in {"provider", "business"}:
        received = db.session.execute(select(Review.id, Review.request_id, Review.rating, Review.comment, Review.created_at, ServiceRequest.title, User.name.label("customer_name")).join(ServiceRequest, ServiceRequest.id == Review.request_id).join(User, User.id == Review.customer_id).where(Review.target_user_id == user.id, Review.status == "published").order_by(Review.created_at.desc(), Review.id.desc()).limit(per+1).offset(offset)).mappings().all(); has_next=len(received)>per; received=received[:per]; summary=rating_summary(user.id)
    return render_template("main/reviews.html", page_title="Reviews — LocalConnect", eligible=eligible, mine=mine, received=received, summary=summary, page=page, has_next=has_next)


@bp.route("/report.php", methods=["GET", "POST"])
@require_login
def report():
    user=current_user(); assert user is not None
    kind=(request.args.get("type") or request.form.get("type") or "").strip()
    try: target_id=int(request.args.get("id") or request.form.get("id") or 0)
    except ValueError: target_id=0
    if kind not in {"provider","business","review"} or target_id<1: abort(404)
    if request.method == "POST":
        try:
            reason=request.form.get("reason", ""); allowed={"fake_profile","wrong_information","spam","fraud_concern","inappropriate_content","other"}
            if reason not in allowed: raise ValueError("Please select a valid report reason.")
            details=clean_text(request.form.get("details", ""),2000,False,"Report details")
            db.session.add(Report(reporter_id=user.id,target_type=kind,target_id=target_id,reason=reason,details=details or None,status="open")); db.session.commit(); flash("Report submitted for admin review.","success")
        except ValueError as exc: db.session.rollback(); flash(str(exc),"error")
        return redirect(f"/report.php?type={kind}&id={target_id}",code=303)
    return render_template("main/report.html",page_title="Report Content — LocalConnect",target_type=kind,target_id=target_id)


@bp.route("/request-details.php", methods=["GET", "POST"])
@require_login
def request_details():
    user=current_user(); assert user is not None
    try: request_id=int(request.args.get("id") or request.form.get("id") or 0)
    except ValueError: request_id=0
    row=db.session.get(ServiceRequest,request_id)
    if not row: abort(404)
    customer=db.session.get(User,row.customer_id); category=db.session.get(Category,row.category_id); service=db.session.get(Service,row.service_id) if row.service_id else None
    provider=db.session.get(User,row.provider_id) if row.provider_id else None; business=db.session.get(User,row.business_id) if row.business_id else None
    is_customer=user.role=="customer" and row.customer_id==user.id
    is_target=(user.role=="provider" and row.provider_id==user.id) or (user.role=="business" and row.business_id==user.id)
    can_claim=user.role in {"provider","business"} and row.request_type=="requirement" and row.status=="pending" and row.provider_id is None and row.business_id is None and bool(db.session.scalar(select(ProviderService.id).where(ProviderService.provider_user_id==user.id,ProviderService.service_id==row.service_id,ProviderService.is_active==1).limit(1)))
    if not is_customer and not is_target and not can_claim and user.role!="admin": abort(403)
    allowed=[]
    if is_customer and row.status in {"pending","accepted"}: allowed=["cancelled"]
    if is_target:
        allowed={"pending":["accepted","rejected"],"accepted":["in_progress","cancelled"],"in_progress":["completed","cancelled"]}.get(row.status,[])
    if request.method=="POST":
        action=request.form.get("action","")
        if action=="claim" and can_claim:
            try:
                locked=db.session.scalar(select(ServiceRequest).where(ServiceRequest.id==request_id).with_for_update())
                if not locked or locked.status!="pending" or locked.provider_id or locked.business_id: raise ValueError("This requirement is no longer available.")
                if user.role=="provider": locked.provider_id=user.id
                else: locked.business_id=user.id
                db.session.add(RequestStatusHistory(request_id=locked.id,status="pending",changed_by=user.id,note="Requirement claimed; awaiting provider acceptance")); create_notification(locked.customer_id,"requirement_claimed","Provider responded to your requirement",f"{user.name} responded to your requirement.",f"request-details.php?id={locked.id}"); db.session.commit(); flash("Requirement assigned to you. You can now accept or reject it.","success"); return redirect("/business/requests.php" if user.role=="business" else "/provider/requests.php",code=303)
            except Exception: db.session.rollback(); flash("This requirement is no longer available.","error"); return redirect("/provider/available-requirements.php",code=303)
        if action=="status":
            new=request.form.get("status","")
            try:
                # Serialize status transitions and re-check ownership + allowed
                # transition against the locked row. This prevents concurrent
                # stale requests from overwriting a newer state.
                locked=db.session.scalar(select(ServiceRequest).where(ServiceRequest.id==request_id).with_for_update())
                if not locked:
                    abort(404)
                locked_is_customer=user.role=="customer" and locked.customer_id==user.id
                locked_is_target=(user.role=="provider" and locked.provider_id==user.id) or (user.role=="business" and locked.business_id==user.id)
                locked_allowed=[]
                if locked_is_customer and locked.status in {"pending","accepted"}:
                    locked_allowed=["cancelled"]
                elif locked_is_target:
                    locked_allowed={"pending":["accepted","rejected"],"accepted":["in_progress","cancelled"],"in_progress":["completed","cancelled"]}.get(locked.status,[])
                if new not in locked_allowed:
                    raise ValueError("That status change is not allowed.")
                note=clean_text(request.form.get("note",""),500,False,"Status note")
                locked.status=new
                db.session.add(RequestStatusHistory(request_id=locked.id,status=new,changed_by=user.id,note=note or None))
                notify=(locked.provider_id or locked.business_id) if locked_is_customer else locked.customer_id
                if notify:
                    create_notification(notify,"request_status","Service request updated",f"Request #{locked.id} is now {new.replace('_',' ').title()}.",f"request-details.php?id={locked.id}")
                db.session.commit(); flash("Request status updated.","success"); target="/customer/requests.php" if user.role=="customer" else ("/business/requests.php" if user.role=="business" else "/provider/requests.php"); return redirect(target,code=303)
            except ValueError as exc:
                db.session.rollback(); flash(str(exc),"error"); return redirect(f"/request-details.php?id={request_id}",code=303)
    history=db.session.execute(select(RequestStatusHistory.status,RequestStatusHistory.note,RequestStatusHistory.created_at,User.name.label("changed_by_name")).join(User,User.id==RequestStatusHistory.changed_by).where(RequestStatusHistory.request_id==request_id).order_by(RequestStatusHistory.created_at,RequestStatusHistory.id)).mappings().all()
    detail={"row":row,"customer":customer,"category":category,"service":service,"provider":provider,"business":business}
    return render_template("main/request_details.html",page_title=f"Request #{request_id} — LocalConnect",detail=detail,history=history,is_customer=is_customer,is_target=is_target,can_claim=can_claim,allowed=allowed)


@bp.get("/about.php")
def about(): return render_template("main/static.html",page_title="About LocalConnect",heading="About LocalConnect",kind="about")
@bp.get("/privacy.php")
def privacy(): return render_template("main/static.html",page_title="Privacy — LocalConnect",heading="Privacy",kind="privacy")
@bp.get("/terms.php")
def terms(): return render_template("main/static.html",page_title="Terms — LocalConnect",heading="Terms",kind="terms")
