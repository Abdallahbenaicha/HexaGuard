"""SecurAx — shared utilities and decorators used across blueprints."""

import io
import logging
import os
import re
import zipfile
from functools import wraps

from flask import jsonify, request
from flask_login import current_user, login_required

from database import get_locked_target, log_event

logger = logging.getLogger(__name__)

# ── Regex ──────────────────────────────────────────────────────────────────────
_UUID_RE = re.compile(r"^[0-9a-f]{32}$")

# ── Upload validation ──────────────────────────────────────────────────────────
_BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".dll",
    ".so", ".dylib", ".bin", ".msi", ".com", ".scr", ".pif",
}
_MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB uncompressed cap (zip bomb guard)


def validate_upload(file_storage, allowed_extensions: set) -> tuple:
    """Return (ok, error_message). Validates extension, size, and zip-bomb."""
    if not file_storage or not file_storage.filename:
        return False, "لم يتم رفع ملف."

    name = file_storage.filename.lower()
    ext  = os.path.splitext(name)[1]

    if ext in _BLOCKED_EXTENSIONS:
        return False, f"نوع الملف '{ext}' محظور لأسباب أمنية."
    if ext not in allowed_extensions:
        return False, f"الامتداد '{ext}' غير مسموح. المسموح: {', '.join(sorted(allowed_extensions))}"

    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > 10 * 1024 * 1024:
        return False, "حجم الملف يتجاوز الحد المسموح (10 MB)."

    if ext == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(file_storage.read()), "r") as zf:
                total = sum(i.file_size for i in zf.infolist())
                if total > _MAX_ZIP_UNCOMPRESSED:
                    return False, "الملف المضغوط يحتوي على بيانات كبيرة جداً (zip bomb محتمل)."
            file_storage.seek(0)
        except zipfile.BadZipFile:
            return False, "الملف ليس ملف ZIP صالحاً."

    return True, ""


# ── Decorators ─────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.has_permission(permission):
                logger.warning(
                    "access denied | user=%s | permission=%s | path=%s",
                    current_user.username, permission, request.path,
                )
                log_event(
                    "access_denied", current_user.username, current_user.id,
                    category="security", resource=request.path,
                    ip_address=request.remote_addr, status="denied",
                    details=f"Missing permission: {permission}",
                )
                return jsonify({"error": "صلاحية غير كافية."}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Target lock helpers ────────────────────────────────────────────────────────

def _normalize_target(raw: str) -> str:
    """Strip protocol / path / port → bare lowercase hostname or IP."""
    t = re.sub(r'^https?://', '', raw.strip())
    t = t.split('/')[0].split('?')[0].split(':')[0]
    return t.lower().strip()


def _check_target_lock(raw_target: str):
    """
    Enforce admin-assigned target restriction.
    Returns (True, None) if allowed, (False, error_response) if blocked.
    """
    if current_user.role == "admin":
        return True, None

    locked = get_locked_target(current_user.id)
    if locked is None:
        return True, None

    normalized = _normalize_target(raw_target)
    if locked == normalized:
        return True, None

    log_event(
        "target_violation", current_user.username, current_user.id,
        category="security", resource=normalized, status="denied",
        details=f"Blocked: tried {normalized!r}, allowed target is {locked!r}",
        ip_address=request.remote_addr,
    )
    return False, (
        jsonify({
            "error": (
                f"غير مسموح. صلاحيات حسابك مقتصرة على الهدف «{locked}» فقط. "
                f"تواصل مع المدير لتغيير الهدف المصرّح به."
            ),
            "allowed_target": locked,
            "forbidden": True,
        }),
        403,
    )
