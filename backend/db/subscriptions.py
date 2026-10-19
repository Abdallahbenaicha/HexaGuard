# Auto-generated modular DB component
import json
import logging
import os
import re
import sqlite3
import threading
import urllib.parse
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

PLANS: dict = {
    "free":       {"label": "Gratuit",    "max_scans_month": 1,     "max_ai_messages": 20,    "price_dzd": 0},
    "starter":    {"label": "Starter",    "max_scans_month": 5,     "max_ai_messages": 100,   "price_dzd": 5000},
    "pro":        {"label": "Pro",        "max_scans_month": 20,    "max_ai_messages": 1000,  "price_dzd": 12000},
    "business":   {"label": "Business",   "max_scans_month": 999,   "max_ai_messages": 5000,  "price_dzd": 25000},
    "agency":     {"label": "Agency",     "max_scans_month": 9999,  "max_ai_messages": 20000, "price_dzd": 40000},
    "enterprise": {"label": "Enterprise", "max_scans_month": 99999, "max_ai_messages": 99999, "price_dzd": 79000},
}


def _cycle_start() -> str:
    """ISO string for the first second of the current calendar month (UTC)."""
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


def _ensure_subscription(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        _exec(
            "INSERT OR IGNORE INTO subscriptions"
            " (user_id, plan, scans_used, cycle_start, created_at)"
            " VALUES (?, 'free', 0, ?, ?)",
            (user_id, _cycle_start(), now),
        )
    except Exception:
        pass


def get_subscription(user_id: int) -> dict:
    _ensure_subscription(user_id)
    row = _get_db().execute(
        "SELECT * FROM subscriptions WHERE user_id=?", (user_id,)
    ).fetchone()
    d = dict(row)
    info = PLANS.get(d["plan"], PLANS["free"])
    d["max_scans_month"] = info["max_scans_month"]
    d["price_dzd"]       = info["price_dzd"]
    d["label"]           = info["label"]
    d["remaining"]       = max(0, info["max_scans_month"] - d["scans_used"])
    return d


def set_subscription(user_id: int, plan: str, notes: str = "",
                     expires_at: str | None = None) -> bool:
    if plan not in PLANS:
        return False
    _ensure_subscription(user_id)
    sub = get_subscription(user_id)
    current_plan = sub.get("plan", "free")
    current_used = sub.get("scans_used", 0)

    _PLAN_RANKS = {"free": 0, "starter": 1, "pro": 2, "enterprise": 3}
    current_rank = _PLAN_RANKS.get(current_plan, 0)
    new_rank = _PLAN_RANKS.get(plan, 0)

    # Only reset scans_used on an actual upgrade to a strictly higher tier
    new_scans_used = 0 if new_rank > current_rank else current_used

    _exec(
        "UPDATE subscriptions"
        " SET plan=?, scans_used=?, cycle_start=?, notes=?, expires_at=?"
        " WHERE user_id=?",
        (plan, new_scans_used, _cycle_start(), notes or None, expires_at, user_id),
    )
    return True


def check_and_consume_quota(user_id: int) -> tuple[bool, int, int]:
    """
    Atomically check quota and consume one scan slot.
    Returns (allowed, scans_used_after, max_per_month).
    Resets counter automatically on new billing cycle.
    Admin users (role='admin') are always allowed.
    """
    # Admins are unrestricted
    row = _get_db().execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
    if row and dict(row).get("role", row[0] if row else "") == "admin":
        return True, 0, 9999

    _ensure_subscription(user_id)
    sub = _get_db().execute(
        "SELECT plan, scans_used, cycle_start FROM subscriptions WHERE user_id=?",
        (user_id,),
    ).fetchone()
    if not sub:
        return True, 0, 999

    sub_d       = dict(sub)
    plan_name   = sub_d["plan"]
    scans_used  = sub_d["scans_used"]
    cycle_start = sub_d["cycle_start"]
    info       = PLANS.get(plan_name, PLANS["free"])
    max_scans  = info["max_scans_month"]

    # Reset if new billing cycle
    current = _cycle_start()
    if cycle_start < current:
        _exec(
            "UPDATE subscriptions SET scans_used=0, cycle_start=? WHERE user_id=?",
            (current, user_id),
        )
        scans_used = 0

    if scans_used >= max_scans:
        return False, scans_used, max_scans

    new_used = scans_used + 1
    _exec(
        "UPDATE subscriptions SET scans_used=? WHERE user_id=?",
        (new_used, user_id),
    )
    return True, new_used, max_scans


def reserve_quota(user_id: int) -> tuple[bool, int, int]:
    """
    Provisionally reserve 1 scan slot for user_id.
    Returns (allowed, scans_used_after, max_per_month).
    """
    return check_and_consume_quota(user_id)


def commit_quota(user_id: int) -> bool:
    """
    Finalize/commit the reserved scan slot upon successful scan completion.
    """
    return True


def release_quota(user_id: int) -> int:
    """
    Roll back / refund 1 scan slot if scan failed or was rejected after reservation.
    Returns updated scans_used count.
    """
    row = _get_db().execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
    if row and dict(row).get("role", row[0] if row else "") == "admin":
        return 0

    _exec(
        "UPDATE subscriptions SET scans_used = MAX(0, COALESCE(scans_used, 1) - 1) WHERE user_id = ?",
        (user_id,),
    )
    sub = get_subscription(user_id)
    return sub.get("scans_used", 0)


def increment_scan_count(user_id: int) -> int:
    """Increment scans_used counter by 1 for user_id and return new scans_used count."""
    _ensure_subscription(user_id)
    _exec(
        "UPDATE subscriptions SET scans_used = COALESCE(scans_used, 0) + 1 WHERE user_id = ?",
        (user_id,),
    )
    sub = get_subscription(user_id)
    return sub.get("scans_used", 0)



def get_user_ai_preferences(user_id: int) -> dict:
    """Return user's AI data sharing opt-out setting and AI quota usage."""
    row = _get_db().execute(
        "SELECT ai_data_sharing_opt_out, ai_messages_used, role FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not row:
        return {"opt_out": False, "messages_used": 0, "max_messages": 20, "remaining": 20}
    r = dict(row)
    sub = get_subscription(user_id)
    plan = sub.get("plan", "free")
    plan_info = PLANS.get(plan, PLANS["free"])
    max_msgs = plan_info.get("max_ai_messages", 20)
    if r.get("role") == "admin":
        max_msgs = 999999
    used = r.get("ai_messages_used", 0)
    return {
        "opt_out": bool(r.get("ai_data_sharing_opt_out", 0)),
        "messages_used": used,
        "max_messages": max_msgs,
        "remaining": max(0, max_msgs - used),
    }


def set_user_ai_opt_out(user_id: int, opt_out: bool) -> bool:
    """Enable or disable external AI data sharing for a user."""
    cur = _exec(
        "UPDATE users SET ai_data_sharing_opt_out=? WHERE id=?",
        (1 if opt_out else 0, user_id),
    )
    return (cur.rowcount if hasattr(cur, "rowcount") else 1) > 0


def check_and_consume_ai_quota(user_id: int) -> tuple[bool, int, int]:
    """
    Atomically check AI quota and consume one message slot.
    Returns (allowed, messages_used_after, max_messages).
    Admins have unlimited quota.
    """
    db = _get_db()
    row = db.execute(
        "SELECT role, ai_messages_used FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row:
        return False, 0, 0
    r = dict(row)
    role = r.get("role", "")
    used = r.get("ai_messages_used", 0)

    if role == "admin":
        _exec("UPDATE users SET ai_messages_used = ai_messages_used + 1 WHERE id=?", (user_id,))
        return True, used + 1, 999999

    sub = get_subscription(user_id)
    plan = sub.get("plan", "free")
    plan_info = PLANS.get(plan, PLANS["free"])
    max_msgs = plan_info.get("max_ai_messages", 20)

    if used >= max_msgs:
        return False, used, max_msgs

    new_used = used + 1
    _exec("UPDATE users SET ai_messages_used=? WHERE id=?", (new_used, user_id))
    return True, new_used, max_msgs


def get_all_subscriptions() -> list[dict]:
    rows = _get_db().execute(
        "SELECT u.id, u.username, u.email, u.role, u.is_active,"
        "  COALESCE(s.plan,'free') AS plan,"
        "  COALESCE(s.scans_used,0) AS scans_used,"
        "  s.cycle_start, s.expires_at, s.notes"
        " FROM users u"
        " LEFT JOIN subscriptions s ON s.user_id=u.id"
        " ORDER BY u.id"
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        info = PLANS.get(d["plan"], PLANS["free"])
        d["max_scans_month"] = info["max_scans_month"]
        d["price_dzd"]       = info["price_dzd"]
        d["label"]           = info["label"]
        d["remaining"]       = max(0, info["max_scans_month"] - d["scans_used"])
        result.append(d)
    return result


def get_monthly_usage_report() -> dict:
    cycle = _cycle_start()
    rows = _get_db().execute(
        "SELECT u.id, u.username,"
        "  COALESCE(s.plan,'free') AS plan,"
        "  COALESCE(s.scans_used,0) AS quota_used,"
        "  COUNT(r.id) AS actual_scans"
        " FROM users u"
        " LEFT JOIN scan_reports r ON r.user_id=u.id AND r.stored_at >= ?"
        " LEFT JOIN subscriptions s ON s.user_id=u.id"
        " WHERE u.is_active=1"
        " GROUP BY u.id ORDER BY actual_scans DESC",
        (cycle,),
    ).fetchall()
    return {"cycle_start": cycle, "users": [dict(r) for r in rows]}


# ── Payment Processing & Verification (fix/round3 item 2) ───────────────────

def record_payment(payment_ref: str, user_id: int, plan: str, amount: float, currency: str = "DZD") -> bool:
    """Record verified payment transaction in payments table.
    
    Enforces uniqueness of payment_ref to prevent transaction replay / reuse.
    Returns True if successfully recorded, False on duplicate or error.
    """
    ref = (payment_ref or "").strip()
    if not ref:
        return False
    now = datetime.now(timezone.utc).isoformat()
    try:
        _exec(
            "INSERT INTO payments (payment_ref, user_id, plan, amount, currency, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (ref, user_id, plan, float(amount), currency.upper(), now),
        )
        return True
    except Exception as exc:
        logger.warning("Failed to record payment '%s': %s", ref, exc)
        return False


def is_payment_ref_used(payment_ref: str) -> bool:
    """Check if payment reference already exists in payments table."""
    ref = (payment_ref or "").strip()
    if not ref:
        return False
    row = _get_db().execute("SELECT 1 FROM payments WHERE payment_ref = ?", (ref,)).fetchone()
    return row is not None


_REF_RE = re.compile(r"^pi_[A-Za-z0-9]{8,64}$")


def _fetch_intent(ref: str, secret: str) -> dict:
    """Fetch PaymentIntent from payment provider API (monkeypatched in tests)."""
    quoted_ref = urllib.parse.quote(ref, safe="")
    req = urllib.request.Request(
        f"https://api.stripe.com/v1/payment_intents/{quoted_ref}",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def verify_payment(payment_ref: str, user_id: int, plan: str) -> tuple[bool, str]:
    """Verify payment with actual provider, checking amount, currency, status, user ownership, and prevent reuse."""
    ref = (payment_ref or "").strip()
    if not ref:
        return False, "Missing payment reference."

    gateway_secret = (os.environ.get("PAYMENT_GATEWAY_SECRET") or os.environ.get("STRIPE_SECRET_KEY") or "").strip()
    if not gateway_secret:
        return False, "No payment gateway configured. Self-service plan upgrades are currently disabled."

    if gateway_secret.startswith("sk_test_") and os.environ.get("FLASK_ENV") == "production":
        return False, "Test gateway key refused in production."

    if not _REF_RE.fullmatch(ref):
        return False, "Invalid payment reference."

    if is_payment_ref_used(ref):
        return False, "Payment reference has already been used."

    plan_info = PLANS.get(plan)
    if not plan_info:
        return False, f"Invalid plan '{plan}'."

    try:
        p_data = _fetch_intent(ref, gateway_secret)
    except Exception as exc:
        logger.warning("Payment gateway verification failed for ref %s: %s", ref, exc)
        return False, "Payment verification failed at payment gateway."

    md = p_data.get("metadata") or {}
    expected_amount = int(plan_info.get("price_dzd", 0)) * 100  # smallest currency unit (cents)
    status = p_data.get("status")
    currency = p_data.get("currency", "").lower()
    amount_received = int(p_data.get("amount_received", p_data.get("amount", 0)))

    ok = (
        status == "succeeded"
        and currency == "dzd"
        and amount_received >= expected_amount
        and str(md.get("user_id")) == str(user_id)
        and md.get("plan") == plan
    )
    if not ok:
        return False, "Payment does not match this account and plan."

    rec_ok = record_payment(ref, user_id, plan, expected_amount / 100.0, "DZD")
    if not rec_ok:
        return False, "Payment reference already used."

    return True, "Payment verified successfully."


