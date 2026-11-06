from __future__ import annotations

import base64
import os
from urllib.parse import urlsplit

from flask import Flask, Response, current_app, g, redirect, request, session


class TrustedProxyHeadersMiddleware:
    """Honor forwarded scheme only from explicitly trusted proxy addresses."""

    def __init__(self, app, enabled: bool, trusted_ips: tuple[str, ...], trusted_hops: int = 1):
        self.app = app
        self.enabled = enabled
        self.trusted_ips = set(trusted_ips)
        self.trusted_hops = max(1, min(5, int(trusted_hops)))

    def __call__(self, environ, start_response):
        remote_addr = environ.get("REMOTE_ADDR")
        if self.enabled and ("*" in self.trusted_ips or remote_addr in self.trusted_ips):
            values = [v.strip().lower() for v in (environ.get("HTTP_X_FORWARDED_PROTO") or "").split(",") if v.strip()]
            if values:
                index = max(0, len(values) - self.trusted_hops)
                forwarded_proto = values[index]
                if forwarded_proto in {"http", "https"}:
                    environ["wsgi.url_scheme"] = forwarded_proto
        return self.app(environ, start_response)


def csp_nonce() -> str:
    nonce = getattr(g, "csp_nonce", None)
    if nonce is None:
        nonce = base64.b64encode(os.urandom(18)).decode("ascii")
        g.csp_nonce = nonce
    return nonce


def _csp_value() -> str:
    nonce = csp_nonce()
    directives = [
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://checkout.razorpay.com",
        "script-src-attr 'none'",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
        "font-src 'self' data: https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob: https://*.razorpay.com",
        "connect-src 'self' https://api.razorpay.com https://*.razorpay.com",
        "frame-src https://api.razorpay.com https://*.razorpay.com",
        "worker-src 'self' blob:",
        "manifest-src 'self'",
    ]
    if current_app.config["APP_ENV"] == "production":
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


def _safe_https_redirect() -> Response | None:
    if current_app.config["APP_ENV"] != "production" or not current_app.config["FORCE_HTTPS"] or request.is_secure:
        return None
    app_url = current_app.config.get("APP_URL", "")
    parts = urlsplit(app_url)
    host = request.host or parts.netloc
    if not host:
        return Response("Production HTTPS configuration is incomplete.", status=503, mimetype="text/plain")
    target = f"https://{host}{request.full_path if request.query_string else request.path}"
    return redirect(target, code=308)


def _hsts_value() -> str:
    value = f"max-age={current_app.config['HSTS_MAX_AGE']}"
    if current_app.config["HSTS_INCLUDE_SUBDOMAINS"]:
        value += "; includeSubDomains"
    if current_app.config["HSTS_PRELOAD"]:
        value += "; preload"
    return value


def register_security(app: Flask) -> None:
    app.wsgi_app = TrustedProxyHeadersMiddleware(
        app.wsgi_app,
        bool(app.config["TRUST_PROXY"]),
        tuple(app.config["TRUSTED_PROXY_IPS"]),
        int(app.config.get("TRUSTED_PROXY_HOPS", 1)),
    )

    @app.before_request
    def enforce_https():
        return _safe_https_redirect()

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers.pop("X-Powered-By", None)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Permissions-Policy"] = (
            'geolocation=(), camera=(), microphone=(), usb=(), interest-cohort=(), '
            'payment=(self "https://checkout.razorpay.com")'
        )
        if current_app.config["APP_ENV"] == "production" and request.is_secure:
            response.headers["Strict-Transport-Security"] = _hsts_value()

        csp_header = (
            "Content-Security-Policy-Report-Only"
            if current_app.config["SECURITY_CSP_MODE"] == "report-only"
            else "Content-Security-Policy"
        )
        response.headers[csp_header] = _csp_value()

        if request.path == "/health":
            response.headers["Cache-Control"] = "no-store, max-age=0"
        elif session.get("user_id"):
            response.headers["Cache-Control"] = "private, no-store, max-age=0"
        return response
