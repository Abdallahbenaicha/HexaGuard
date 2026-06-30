"""
HexaGuard Security Platform — Application factory.

All routes live in blueprints/. This file only wires extensions,
middleware, blueprints, and the user-loader together.
"""

import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, url_for

from extensions import init_extensions, login_manager
from middleware import register_middleware

load_dotenv()

# Some hosting platforms inject HTTP(S)_PROXY into the container env for
# egress monitoring — that breaks the scanners, which must reach arbitrary
# targets directly. Strip it so `requests` (trust_env=True by default)
# never routes through it.
for _var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_var, None)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

_IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")

    SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is not set. Add it to .env:\n"
            "  SECRET_KEY=your-very-long-random-secret-key"
        )

    app.config.update(
        SECRET_KEY=SECRET_KEY,
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="None" if _IS_PRODUCTION else "Lax",
        SESSION_COOKIE_SECURE=_IS_PRODUCTION,
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        PERMANENT_SESSION_LIFETIME=1800,
        RATELIMIT_STORAGE_URI=os.environ.get("REDIS_URL", "memory://"),
    )

    init_extensions(app)
    register_middleware(app)

    # ── User loader ──────────────────────────────────────────────────────────
    from models import load_user_from_db

    @login_manager.user_loader
    def load_user(user_id: str):
        return load_user_from_db(user_id)

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Authentication required. Please log in."}), 401
        return redirect(url_for("auth.login"))

    # ── Blueprints ───────────────────────────────────────────────────────────
    from blueprints.auth                import auth_bp
    from blueprints.scans               import scans_bp
    from blueprints.reports             import reports_bp
    from blueprints.admin               import admin_bp
    from blueprints.ai_routes           import ai_bp
    from blueprints.scheduled           import scheduled_bp
    from blueprints.extra_scans         import extra_bp
    from blueprints.domain_verification import domain_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(scheduled_bp)
    app.register_blueprint(extra_bp)
    app.register_blueprint(domain_bp)

    # ── DB init ──────────────────────────────────────────────────────────────
    from database import init_db
    with app.app_context():
        init_db()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
