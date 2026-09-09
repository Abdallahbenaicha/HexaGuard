# Auto-generated modular DB component
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
import bcrypt

logger = logging.getLogger(__name__)

try:
    from db.connection import (
        _get_db, _exec, _norm, _count_severities, _UNSET, _local, _resolve_db_path, DB_PATH
    )
except ImportError:
    from backend.db.connection import (
        _get_db, _exec, _norm, _count_severities, _UNSET, _local, _resolve_db_path, DB_PATH
    )

def get_user_by_username(username: str) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
    ).fetchone()
    return _norm(row)


def get_user_by_id(user_id: int) -> dict | None:
    row = _get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _norm(row)


def get_all_users(page: int = 1, per_page: int = 100) -> list[dict]:
    offset = (page - 1) * per_page
    return [
        _norm(r) for r in _get_db().execute(
            "SELECT * FROM users ORDER BY id LIMIT ? OFFSET ?", (per_page, offset)
        ).fetchall()
    ]


def count_users() -> int:
    return _get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(username: str, password: str, role: str = "analyst",
                permissions=None, created_by: str | None = None,
                allowed_target: str | None = None,
                email: str | None = None) -> tuple[bool, str]:
    if permissions is None:
        if role == "admin":
            permissions = ["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"]
        elif role == "analyst":
            permissions = ["run_scan", "view_reports"]
        else:
            permissions = ["view_reports"]
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()
    # allowed_target → stored in locked_target column
    target_val = allowed_target.strip().lower() if allowed_target and allowed_target.strip() else None
    email_val  = email.strip().lower() if email and email.strip() else None
    try:
        _exec(
            "INSERT INTO users (username,email,password_hash,role,permissions,is_active,created_at,created_by,locked_target)"
            " VALUES (?,?,?,?,?,1,?,?,?)",
            (username, email_val, pw_hash, role, json.dumps(permissions), now, created_by, target_val),
        )
        return True, "User created successfully."
    except Exception as exc:
        msg = str(exc).lower()
        if "unique" in msg or "duplicate" in msg or "1062" in msg:
            return False, "Username already exists."
        logger.error("create_user: %s", exc)
        return False, f"Database error: {exc}"


def get_allowed_scanners(user_id: int) -> list[str] | None:
    """Return the whitelist of allowed scanner slugs, or None if unrestricted."""
    row = _get_db().execute(
        "SELECT allowed_scanners FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row:
        return None
    raw = row[0] if isinstance(row, (list, tuple)) else row.get("allowed_scanners")
    if raw is None:
        return None  # unrestricted
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else None
    except Exception:
        return None


# ── Allowed fields whitelist for user updates (ARCH-01) ──────────────────────
_ALLOWED_USER_FIELDS = {
    "role",
    "permissions",
    "is_active",
    "password_hash",
    "failed_attempts",
    "locked_until",
    "locked_target",
    "allowed_scanners",
}


def update_user(uid: int, role=None, permissions=None, is_active=None,
                new_password=None, failed_attempts=None, locked_until=None,
                reset_locked_target=False, locked_target_value=_UNSET,
                allowed_scanners=_UNSET, **kwargs) -> tuple[bool, str]:
    if kwargs:
        disallowed = set(kwargs.keys()) - _ALLOWED_USER_FIELDS
        if disallowed:
            return False, f"Disallowed fields: {', '.join(sorted(disallowed))}"

    fields, values = [], []
    if role            is not None: fields.append("role=?");             values.append(role)
    if permissions     is not None: fields.append("permissions=?");      values.append(json.dumps(permissions))
    if is_active       is not None: fields.append("is_active=?");        values.append(int(is_active))
    if new_password    is not None:
        ph = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        fields.append("password_hash=?"); values.append(ph)
    if failed_attempts is not None: fields.append("failed_attempts=?");  values.append(failed_attempts)
    if locked_until    is not None: fields.append("locked_until=?");     values.append(locked_until)
    if reset_locked_target:
        fields.append("locked_target=?"); values.append(None)
    elif locked_target_value is not _UNSET:
        fields.append("locked_target=?"); values.append(locked_target_value)
    if allowed_scanners is not _UNSET:
        # None → unrestricted (NULL in DB), list → JSON whitelist
        fields.append("allowed_scanners=?")
        values.append(None if allowed_scanners is None else json.dumps(list(allowed_scanners)))

    for k, v in kwargs.items():
        if k == "password_hash" and v is not None:
            fields.append("password_hash=?")
            values.append(v)
        elif k in {"role", "locked_target"} and v is not None:
            fields.append(f"{k}=?")
            values.append(v)
        elif k in {"is_active", "failed_attempts"} and v is not None:
            fields.append(f"{k}=?")
            values.append(int(v))
        elif k == "locked_until" and v is not None:
            fields.append("locked_until=?")
            values.append(v)
        elif k in {"permissions", "allowed_scanners"} and v is not None:
            fields.append(f"{k}=?")
            values.append(json.dumps(v) if isinstance(v, (list, dict)) else v)

    if not fields:
        return True, ""
    values.append(uid)
    _exec(f"UPDATE users SET {', '.join(fields)} WHERE id=?", tuple(values))  # nosec B608
    return True, "Updated successfully."


def update_last_login(user_id: int):
    _exec(
        "UPDATE users SET last_login=?, login_count=login_count+1 WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id),
    )


def get_locked_target(user_id: int) -> str | None:
    """Return the target (hostname/IP) that this analyst is locked to, or None if unset."""
    row = _get_db().execute(
        "SELECT locked_target FROM users WHERE id=?", (user_id,)
    ).fetchone()
    return row["locked_target"] if row else None


def set_locked_target(user_id: int, target: str) -> None:
    """Lock an analyst account to a specific target on their first scan."""
    _exec("UPDATE users SET locked_target=? WHERE id=?", (target, user_id))


def update_user_totp(user_id: int, secret: str, enabled: bool) -> tuple[bool, str]:
    _exec("UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?",
          (secret, int(enabled), user_id))
    return True, ""


def set_api_token(user_id: int, token: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        _exec("UPDATE users SET api_token=?, api_token_created=? WHERE id=?",
              (token, now, user_id))
    except Exception:
        pass  # api_token column may not exist on very old DBs


def revoke_api_token(user_id: int) -> None:
    try:
        _exec("UPDATE users SET api_token=NULL, api_token_created=NULL WHERE id=?", (user_id,))
    except Exception:
        pass


def get_user_by_api_token(token: str) -> dict | None:
    try:
        row = _get_db().execute(
            "SELECT * FROM users WHERE api_token=? AND is_active=1", (token,)
        ).fetchone()
        return _norm(row)
    except Exception:
        return None


def delete_user(uid: int) -> tuple[bool, str]:
    """Soft delete — deactivates the user without removing the record."""
    _exec("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    return True, "User deactivated."


def hard_delete_user(uid: int) -> tuple[bool, str]:
    _exec("DELETE FROM users WHERE id=?", (uid,))
    return True, "User deleted."


def count_active_admins() -> int:
    return _get_db().execute(
        "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
    ).fetchone()[0]


# ── Audit log ─────────────────────────────────────────────────────────────────

