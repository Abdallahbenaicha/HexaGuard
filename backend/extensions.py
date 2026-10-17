"""
SecuraX — shared Flask extensions.
All extension objects live here and are bound to the app via init_extensions().
Blueprints import from here so they never touch the app object directly.
"""

import os
import re

from flask import request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

csrf          = CSRFProtect()
login_manager = LoginManager()
limiter       = Limiter(
    key_func=get_remote_address,
    default_limits=["500/hour", "200/minute"],
)

_DEFAULT_ORIGINS = (
    # Production frontends
    "https://hexa-gaurd.vercel.app,"
    "https://hexaguard.vercel.app,"
    "https://securax.vercel.app,"
    "https://abdallahbenaicha-hexaguard.hf.space,"
    # Local development
    "http://localhost:3000,"
    "http://localhost:3001,"
    "http://localhost:5173,"
    "http://127.0.0.1:3000,"
    "http://127.0.0.1:3001,"
    "http://127.0.0.1:5173"
)

# Also add any extra origins from the environment variable
_ENV_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = list({
    o.strip()
    for o in (_DEFAULT_ORIGINS + "," + _ENV_ORIGINS).split(",")
    if o.strip()
})


def init_extensions(app) -> None:
    csrf.init_app(app)

    # Targeted CSRF exemption: only exempt unauthenticated auth endpoints and Bearer tokens,
    # NEVER the entire /api/* hierarchy (which would bypass CSRF on subscription, scans, etc.)
    _EXEMPT_AUTH_ENDPOINTS = {
        "auth.api_login",
        "auth.api_register",
        "auth.api_totp_verify",
        "auth.login",
    }

    def _targeted_csrf_hook():
        if not request.endpoint:
            return
        from flask import current_app
        view = current_app.view_functions.get(request.endpoint)
        if not view:
            return
        dest = f"{view.__module__}.{view.__name__}"

        # 1. Allow unauthenticated authentication endpoints without CSRF token
        if request.endpoint in _EXEMPT_AUTH_ENDPOINTS or request.path in (
            "/api/auth/login", "/api/auth/register", "/api/auth/totp-verify", "/login"
        ):
            csrf._exempt_views.add(dest)
            return

        # 2. Token-authenticated API requests (Bearer sx_...) don't rely on ambient browser cookies
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer sx_") or auth_hdr.startswith("Bearer ey"):
            csrf._exempt_views.add(dest)
            return

    app.before_request_funcs.setdefault(None, []).insert(0, _targeted_csrf_hook)

    login_manager.login_view    = "auth.login"
    login_manager.login_message = "يرجى تسجيل الدخول للمتابعة."
    login_manager.init_app(app)

    limiter.init_app(app)

    CORS(
        app,
        resources={
            r"/*": {
                "origins": ALLOWED_ORIGINS,
                "supports_credentials": True,
                "allow_headers": ["Content-Type", "X-CSRFToken", "Authorization", "Accept"],
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "expose_headers": ["X-CSRFToken"],
                "max_age": 600,
            }
        },
        supports_credentials=True,
    )
