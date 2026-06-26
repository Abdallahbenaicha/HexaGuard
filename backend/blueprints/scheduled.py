"""SecurAx — Scheduled Scans API blueprint."""

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

import database as db

scheduled_bp = Blueprint("scheduled", __name__)

_VALID_TYPES  = {"web", "network", "dast", "ssl", "server", "sast", "dependencies"}
_VALID_CRONS  = {"daily", "weekly", "monthly"}


def _require_login():
    if not current_user.is_authenticated:
        return jsonify({"ok": False, "error": "Authentication required."}), 401
    return None


# ── List user's scheduled scans ───────────────────────────────────────────────

@scheduled_bp.get("/api/scheduled-scans")
@login_required
def list_scheduled():
    scans = db.get_user_scheduled_scans(current_user.id)
    return jsonify({"ok": True, "scheduled": scans})


# ── Create a scheduled scan ───────────────────────────────────────────────────

@scheduled_bp.post("/api/scheduled-scans")
@login_required
def create_scheduled():
    body      = request.get_json(silent=True) or {}
    scan_type = (body.get("scan_type") or "").strip().lower()
    target    = (body.get("target") or "").strip()
    cron_expr = (body.get("cron_expr") or "daily").strip().lower()

    if scan_type not in _VALID_TYPES:
        return jsonify({"ok": False, "error": f"Invalid scan_type. Choose from: {', '.join(_VALID_TYPES)}"}), 400
    if not target:
        return jsonify({"ok": False, "error": "target is required."}), 400
    if cron_expr not in _VALID_CRONS:
        return jsonify({"ok": False, "error": "cron_expr must be daily, weekly, or monthly."}), 400

    # Limit per user
    existing = db.get_user_scheduled_scans(current_user.id)
    if len(existing) >= 10:
        return jsonify({"ok": False, "error": "Maximum 10 scheduled scans per user."}), 429

    sched_id = db.create_scheduled_scan(
        user_id=current_user.id,
        username=current_user.username,
        scan_type=scan_type,
        target=target,
        cron_expr=cron_expr,
    )
    return jsonify({"ok": True, "id": sched_id, "message": "Scheduled scan created."}), 201


# ── Toggle active/paused ──────────────────────────────────────────────────────

@scheduled_bp.patch("/api/scheduled-scans/<int:sched_id>")
@login_required
def toggle_scheduled(sched_id):
    body   = request.get_json(silent=True) or {}
    active = bool(body.get("is_active", True))
    ok     = db.toggle_scheduled_scan(sched_id, current_user.id, active)
    if not ok:
        return jsonify({"ok": False, "error": "Scheduled scan not found."}), 404
    return jsonify({"ok": True, "is_active": active})


# ── Delete a scheduled scan ───────────────────────────────────────────────────

@scheduled_bp.delete("/api/scheduled-scans/<int:sched_id>")
@login_required
def delete_scheduled(sched_id):
    ok = db.delete_scheduled_scan(sched_id, current_user.id)
    if not ok:
        return jsonify({"ok": False, "error": "Scheduled scan not found."}), 404
    return jsonify({"ok": True, "message": "Deleted."})
