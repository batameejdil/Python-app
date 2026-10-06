from __future__ import annotations

from datetime import datetime
from urllib.parse import urlencode

from flask import Flask, request
from flask_wtf.csrf import generate_csrf

import models  # noqa: F401
from config.settings import BaseConfig, TestingConfig, production_config_errors
from extensions import csrf, db
from routes import BLUEPRINTS
from routes.errors import register_error_handlers
from services.auth_service import dashboard_for, unread_notification_count
from utils.auth import current_user, install_session_lifecycle
from utils.logging import configure_logging
from utils.observability import register_observability
from utils.security import csp_nonce, register_security
from services.storage_service import ensure_storage_ready


def create_app(config_object=None) -> Flask:
    config_object = config_object or BaseConfig
    app = Flask(
        __name__,
        static_folder="assets",
        static_url_path="/assets",
        template_folder="templates",
    )
    app.config.from_object(config_object)

    if app.config["APP_ENV"] == "production" and not app.config.get("TESTING"):
        errors = production_config_errors()
        if errors:
            raise RuntimeError("Production configuration invalid: " + " | ".join(errors))

    configure_logging(app)
    if app.config.get("UPLOAD_STORAGE_BACKEND") != "filesystem":
        raise RuntimeError("Unsupported upload storage backend.")
    ensure_storage_ready(app, writable_probe=app.config["APP_ENV"] == "production" and not app.config.get("TESTING"))

    db.init_app(app)
    csrf.init_app(app)
    install_session_lifecycle(app)
    register_security(app)
    register_observability(app)

    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)

    register_error_handlers(app)

    def lc_url(path: str = "") -> str:
        base = app.config.get("APP_BASE_PATH", "/") or "/"
        if base == "/":
            return "/" + path.lstrip("/")
        return base.rstrip("/") + "/" + path.lstrip("/")

    def page_url(page_number: int) -> str:
        args = request.args.to_dict(flat=False)
        args["page"] = [str(max(1, int(page_number)))]
        query = urlencode(args, doseq=True)
        return request.path + ("?" + query if query else "")

    @app.context_processor
    def template_helpers():
        try:
            user = current_user()
        except Exception:
            # Keep safe error/public templates renderable if the database is unavailable.
            app.logger.exception("Unable to load current user for template context")
            db.session.rollback()
            user = None
        count = 0
        if user:
            try:
                count = unread_notification_count(user.id)
            except Exception:
                app.logger.exception("Unable to load unread notification count")
                db.session.rollback()
        return {
            "csp_nonce": csp_nonce,
            "csrf_token": generate_csrf,
            "lc_url": lc_url,
            "dashboard_url": lambda role: lc_url(dashboard_for(role).lstrip("/")),
            "nav_user": user,
            "nav_notification_count": count,
            "current_year": datetime.now().year,
            "page_url": page_url,
        }

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=app.config["DEBUG"])
