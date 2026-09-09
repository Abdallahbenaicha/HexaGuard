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

def log_event(action: str, username: str = "", user_id: int | None = None,
              category: str = "general", resource: str = "", ip_address: str = "",
              user_agent: str = "", status: str = "success", details: str = "", **_):
    try:
        _exec(
            "INSERT INTO audit_logs"
            " (action,username,user_id,category,resource,ip_address,user_agent,status,details,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (action, username, user_id, category, resource, ip_address,
             user_agent, status, details, datetime.now(timezone.utc).isoformat()),
        )
    except Exception as exc:
        logger.warning("log_event failed: %s", exc)


def get_audit_log(user_id: int | None = None, category: str | None = None,
                  action: str | None = None, limit: int = 200,
                  date_from: str | None = None, date_to: str | None = None,
                  page: int = 1, per_page: int | None = None) -> tuple[list[dict], int]:
    clauses, params = [], []
    if user_id   is not None: clauses.append("user_id=?");         params.append(user_id)
    if category:              clauses.append("category=?");         params.append(category)
    if action:                clauses.append("action LIKE ?");      params.append(f"%{action}%")
    if date_from:             clauses.append("created_at >= ?");    params.append(date_from)
    if date_to:               clauses.append("created_at <= ?");    params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    db    = _get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]  # nosec B608
    if per_page:
        offset = (max(page, 1) - 1) * per_page
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",  # nosec B608
            params + [per_page, offset],
        ).fetchall()
    else:
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ?",  # nosec B608
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows], total


def get_audit_stats() -> dict:
    db = _get_db()
    total  = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    failed = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE status='failed'"
    ).fetchone()[0]
    by_cat = db.execute(
        "SELECT category, COUNT(*) as c FROM audit_logs GROUP BY category ORDER BY c DESC"
    ).fetchall()
    recent = db.execute(
        "SELECT username, action, created_at FROM audit_logs "
        "WHERE category='auth' ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_events":  total,
        "failed_events": failed,
        "by_category":   [{"category": r["category"], "count": r["c"]} for r in by_cat],
        "recent_logins": [dict(r) for r in recent],
    }


# ── Report functions ──────────────────────────────────────────────────────────

