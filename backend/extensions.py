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

_ENV_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]

ALLOWED_ORIGINS = [
    re.compile(r"^https://.*\.vercel\.app$"),
    re.compile(r"^https://.*\.hf\.space$"),
    re.compile(r"^http://localhost(:\d+)?$"),
    re.compile(r"^http://127\.0\.0\.1(:\d+)?$"),
    "https://hexa-gaurd.vercel.app",
    "https://hexaguard.vercel.app",
    "https://securax.vercel.app",
    "https://abdallahbenaicha-hexaguard.hf.space",
] + _ENV_ORIGINS


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
