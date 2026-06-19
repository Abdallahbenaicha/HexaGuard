"""SecurAx — request/response middleware (CSP nonce, security headers)."""

import os
import secrets

from flask import g, request

from extensions import ALLOWED_ORIGINS

_IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"


def register_middleware(app) -> None:
    @app.before_request
    def set_csp_nonce():
        g.csp_nonce = secrets.token_hex(16)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "SAMEORIGIN"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Strict-Transport-Security"]  = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"

        nonce = getattr(g, "csp_nonce", "")
        _frontend_origins = " ".join(
            o for o in ALLOWED_ORIGINS if o.startswith("https://")
        ) or "'self'"
        _connect_src = f"'self' {_frontend_origins}" if _IS_PRODUCTION else "'self'"
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"img-src 'self' data: https:; "
            f"connect-src {_connect_src}; "
            f"font-src 'self' data:; "
            f"frame-ancestors 'self';"
        )
        if nonce:
            response.headers["X-CSP-Nonce"] = nonce
        if "text/html" in response.headers.get("Content-Type", ""):
            response.headers["Content-Type"] = "text/html; charset=utf-8"
        if _IS_PRODUCTION:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        return response

    @app.errorhandler(400)
    def bad_request(e):
        from flask import jsonify
        return jsonify({"error": "طلب غير صالح."}), 400

    @app.errorhandler(403)
    def forbidden(e):
        from flask import jsonify
        return jsonify({"error": "وصول مرفوض."}), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import jsonify
        return jsonify({"error": "المورد غير موجود."}), 404

    @app.errorhandler(413)
    def file_too_large(e):
        from flask import jsonify
        return jsonify({"error": "حجم الملف كبير جداً. الحد الأقصى 25MB."}), 413

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        from flask import jsonify
        return jsonify({"error": "تجاوزت الحد المسموح من الطلبات. حاول لاحقاً."}), 429

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        import logging
        from flask import jsonify
        logging.getLogger(__name__).exception("خطأ غير متوقع")
        return jsonify({"error": "خطأ داخلي في الخادم."}), 500
