"""
SecurAx — shared Flask extensions.
All extension objects live here and are bound to the app via init_extensions().
Blueprints import from here so they never touch the app object directly.
"""

import os

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
    default_limits=["200/hour", "50/minute"],
)

_DEFAULT_ORIGINS = (
    "http://localhost:3000,"
    "http://localhost:3001,"
    "http://localhost:5173,"
    "http://127.0.0.1:3000,"
    "http://127.0.0.1:3001,"
    "http://127.0.0.1:5173"
)
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]


def init_extensions(app) -> None:
    csrf.init_app(app)

    # Pre-CSRF hook: auto-exempt all /api/* routes.
    # Flask-WTF checks  f"{view.__module__}.{view.__name__}"  (not the endpoint name),
    # so we must construct the same key and add it to _exempt_views before protect() runs.
    def _auto_exempt_api_from_csrf():
        if request.path.startswith("/api/") and request.endpoint:
            from flask import current_app
            view = current_app.view_functions.get(request.endpoint)
            if view:
                csrf._exempt_views.add(f"{view.__module__}.{view.__name__}")

    app.before_request_funcs.setdefault(None, []).insert(0, _auto_exempt_api_from_csrf)

    login_manager.login_view    = "auth.login"
    login_manager.login_message = "يرجى تسجيل الدخول للمتابعة."
    login_manager.init_app(app)

    limiter.init_app(app)

    CORS(
        app,
        origins=ALLOWED_ORIGINS,
        supports_credentials=True,
        allow_headers=["Content-Type", "X-CSRFToken", "Authorization", "Accept"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        expose_headers=["X-CSRFToken"],
        max_age=600,
    )
