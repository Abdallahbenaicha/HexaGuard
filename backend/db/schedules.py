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

def create_scheduled_scan(user_id: int, username: str, scan_type: str,
                          target: str, cron_expr: str = "daily") -> int:
    from datetime import timedelta
    next_run = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    cur = _exec(
        "INSERT INTO scheduled_scans"
        " (user_id,username,scan_type,target,cron_expr,is_active,next_run_at,created_at)"
        " VALUES (?,?,?,?,?,1,?,?)",
        (user_id, username, scan_type, target, cron_expr, next_run,
         datetime.now(timezone.utc).isoformat()),
    )
    return cur.lastrowid


def get_user_scheduled_scans(user_id: int) -> list[dict]:
    rows = _get_db().execute(
        "SELECT * FROM scheduled_scans WHERE user_id=? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_scheduled_scans() -> list[dict]:
    rows = _get_db().execute(
        "SELECT * FROM scheduled_scans WHERE is_active=1 ORDER BY next_run_at ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_due_scheduled_scans(now_iso: str | None = None) -> list[dict]:
    """Return all active scheduled scans where next_run_at <= now."""
    if not now_iso:
        now_iso = datetime.now(timezone.utc).isoformat()
    rows = _get_db().execute(
        "SELECT * FROM scheduled_scans WHERE is_active=1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at ASC",
        (now_iso,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_scheduled_scan_run(sched_id: int, last_run_at: str, next_run_at: str) -> None:
    _exec(
        "UPDATE scheduled_scans SET last_run_at=?, next_run_at=? WHERE id=?",
        (last_run_at, next_run_at, sched_id),
    )


def toggle_scheduled_scan(sched_id: int, user_id: int, active: bool) -> bool:
    cur = _exec(
        "UPDATE scheduled_scans SET is_active=? WHERE id=? AND user_id=?",
        (int(active), sched_id, user_id),
    )
    return (cur.rowcount if hasattr(cur, "rowcount") else 1) > 0


def delete_scheduled_scan(sched_id: int, user_id: int) -> bool:
    cur = _exec(
        "DELETE FROM scheduled_scans WHERE id=? AND user_id=?",
        (sched_id, user_id),
    )
    return (cur.rowcount if hasattr(cur, "rowcount") else 1) > 0


# ── Subscription / Plan Management ───────────────────────────────────────────

PLANS: dict = {
    "free":       {"label": "Gratuit",    "max_scans_month": 1,     "max_ai_messages": 20,    "price_dzd": 0},
    "starter":    {"label": "Starter",    "max_scans_month": 5,     "max_ai_messages": 100,   "price_dzd": 5000},
    "pro":        {"label": "Pro",        "max_scans_month": 20,    "max_ai_messages": 1000,  "price_dzd": 12000},
    "business":   {"label": "Business",   "max_scans_month": 999,   "max_ai_messages": 5000,  "price_dzd": 25000},
    "agency":     {"label": "Agency",     "max_scans_month": 9999,  "max_ai_messages": 20000, "price_dzd": 40000},
    "enterprise": {"label": "Enterprise", "max_scans_month": 99999, "max_ai_messages": 99999, "price_dzd": 79000},
}


