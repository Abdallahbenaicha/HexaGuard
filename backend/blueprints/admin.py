"""SecurAx — admin blueprint.

Handles both HTML admin panel routes (Jinja2) and the JSON admin API
consumed by the React frontend.
"""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from database import (
    count_active_admins, count_users, delete_report, get_all_reports,
    get_all_users, get_audit_log, get_audit_stats, get_system_stats,
    get_top_vulnerabilities, get_user_by_id, hard_delete_user,
    log_event, update_user, create_user,
    get_all_subscriptions, set_subscription, get_monthly_usage_report, PLANS,
)
from extensions import limiter
from forms import check_password_complexity
from utils import _normalize_target, _UUID_RE, admin_required

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__)


# ════════════════════════════════════════════════════════════════════════════
#  HTML ADMIN ROUTES  (served via Flask/Jinja2 templates)
# ════════════════════════════════════════════════════════════════════════════

@admin_bp.route("/admin")
@admin_required
def admin_hub():
    stats     = get_system_stats()
    top_vulns = get_top_vulnerabilities(limit=10)
    return render_template("admin_hub.html", stats=stats, top_vulns=top_vulns,
                           user=current_user.username)


@admin_bp.route("/admin/users")
@admin_required
def admin_users():
    users = get_all_users()
    return render_template("users.html", users=users, user=current_user.username)


@admin_bp.route("/admin/users/create", methods=["POST"])
@admin_required
@limiter.limit("20/minute")
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    role     = request.form.get("role", "analyst")

    if not username or not password:
        flash("اسم المستخدم وكلمة المرور مطلوبان.", "error")
        return redirect(url_for("admin.admin_users"))

    if password != confirm:
        flash("كلمة المرور وتأكيدها غير متطابقتين.", "error")
        return redirect(url_for("admin.admin_users"))

    ok, msg = check_password_complexity(password)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("admin.admin_users"))

    ok, msg = create_user(username, password, role, created_by=current_user.username)
    if ok:
        log_event("user_created", current_user.username, current_user.id,
                  category="admin", resource=username, status="success")
        flash(f"تم إنشاء المستخدم «{username}» بنجاح.", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/users/<int:uid>/update", methods=["POST"])
@admin_required
def admin_update_user(uid: int):
    data         = request.get_json(silent=True) or {}
    role         = data.get("role")
    permissions  = data.get("permissions")
    is_active    = data.get("is_active")
    new_password = data.get("new_password")

    if new_password:
        ok, msg = check_password_complexity(new_password)
        if not ok:
            return jsonify({"error": msg}), 400

    ok, msg = update_user(uid, role=role, permissions=permissions,
                           is_active=is_active, new_password=new_password)
    if ok:
        log_event("user_updated", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid: int):
    if uid == current_user.id:
        flash("لا يمكنك حذف حسابك الخاص.", "error")
        return redirect(url_for("admin.admin_users"))
    ok, msg = hard_delete_user(uid)
    if ok:
        log_event("user_deleted", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
        flash("تم حذف المستخدم بنجاح.", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/scans")
@admin_required
def admin_scans():
    filter_user = request.args.get("user", "").strip()
    filter_type = request.args.get("type", "").strip()
    all_reports = get_all_reports(limit=500)
    if filter_user:
        all_reports = [r for r in all_reports
                       if filter_user.lower() in (r.get("username") or "").lower()]
    if filter_type:
        all_reports = [r for r in all_reports if r.get("scan_type") == filter_type]
    top_vulns = get_top_vulnerabilities(limit=10)
    return render_template(
        "admin_scans.html",
        reports=all_reports, top_vulns=top_vulns,
        filter_user=filter_user, filter_type=filter_type,
        user=current_user.username,
    )


@admin_bp.route("/admin/scans/<token>/delete", methods=["POST"])
@admin_required
def admin_delete_scan(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "رمز التقرير غير صالح."}), 400
    ok, msg = delete_report(token)
    if ok:
        log_event("scan_deleted", current_user.username, current_user.id,
                  category="admin", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/admin/audit")
@admin_required
def admin_audit():
    uid      = request.args.get("user_id", type=int)
    category = request.args.get("category")
    action   = request.args.get("action")
    logs, _  = get_audit_log(user_id=uid, category=category, action=action, limit=200)
    stats    = get_audit_stats()
    return render_template(
        "audit_log.html",
        logs=logs, stats=stats, user=current_user.username,
    )


# ════════════════════════════════════════════════════════════════════════════
#  JSON ADMIN API  (consumed by the React SPA)
# ════════════════════════════════════════════════════════════════════════════

@admin_bp.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    stats     = get_system_stats()
    top_vulns = get_top_vulnerabilities(limit=10)
    return jsonify({"stats": dict(stats), "top_vulns": list(top_vulns)})


@admin_bp.route("/api/admin/users")
@admin_required
def api_admin_users():
    page     = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(max(per_page, 1), 200)
    users    = get_all_users(page=page, per_page=per_page)
    total    = count_users()
    return jsonify({
        "users":    [dict(u) for u in users],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, -(-total // per_page)),
    })


@admin_bp.route("/api/admin/users", methods=["POST"])
@admin_required
@limiter.limit("20/minute")
def api_admin_create_user():
    data           = request.get_json(silent=True) or {}
    username       = (data.get("username") or "").strip()
    password       = data.get("password", "")
    confirm        = data.get("confirm_password", "")
    role           = data.get("role", "analyst")
    allowed_target = (data.get("allowed_target") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400
    if password != confirm:
        return jsonify({"ok": False, "error": "Passwords do not match."}), 400

    ok, msg = check_password_complexity(password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    normalized_target = _normalize_target(allowed_target) if allowed_target else None
    ok, msg = create_user(
        username, password, role,
        created_by=current_user.username,
        allowed_target=normalized_target,
    )
    if ok:
        log_event("user_created", current_user.username, current_user.id,
                  category="admin", resource=username, status="success",
                  details=f"role={role} allowed_target={normalized_target or 'unrestricted'}")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@admin_required
def api_admin_update_user(uid: int):
    data                = request.get_json(silent=True) or {}
    role                = data.get("role")
    permissions         = data.get("permissions")
    is_active           = data.get("is_active")
    new_password        = data.get("new_password")
    reset_locked_target = bool(data.get("reset_locked_target", False))
    reset_failed        = bool(data.get("reset_failed_attempts", False))
    set_allowed_target  = data.get("set_allowed_target")

    if new_password:
        ok, msg = check_password_complexity(new_password)
        if not ok:
            return jsonify({"ok": False, "error": msg}), 400

    from database import _UNSET as _DB_UNSET
    locked_target_value = _DB_UNSET
    audit_action = "user_updated"

    if reset_locked_target:
        audit_action = "target_lock_reset"
    elif set_allowed_target is not None:
        raw = set_allowed_target.strip()
        if raw:
            locked_target_value = _normalize_target(raw)
            audit_action = "target_assigned"
        else:
            locked_target_value = None
            audit_action = "target_lock_reset"

    from database import _UNSET as _DB_UNSET2
    # Scanner permissions: accept list or None (unrestricted)
    scanner_key = "allowed_scanners"
    allowed_scanners = _DB_UNSET2
    if scanner_key in data:
        raw_scanners = data[scanner_key]
        # None → unrestricted, list → whitelist
        allowed_scanners = raw_scanners if isinstance(raw_scanners, list) else None

    ok, msg = update_user(
        uid,
        role=role,
        permissions=permissions,
        is_active=is_active,
        new_password=new_password,
        reset_locked_target=reset_locked_target,
        locked_target_value=locked_target_value,
        failed_attempts=0 if reset_failed else None,
        allowed_scanners=allowed_scanners,
    )
    if ok:
        log_event(audit_action, current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success",
                  details=f"scanners={allowed_scanners if allowed_scanners is not _DB_UNSET2 else 'unchanged'}")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def api_admin_delete_user(uid: int):
    if uid == current_user.id:
        return jsonify({"ok": False, "error": "Cannot delete your own account."}), 400
    target_row = get_user_by_id(uid)
    if target_row and target_row["role"] == "admin" and count_active_admins() <= 1:
        return jsonify({"ok": False, "error": "Cannot delete the last active admin account."}), 400
    ok, msg = hard_delete_user(uid)
    if ok:
        log_event("user_deleted", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/api/admin/scans")
@admin_required
def api_admin_scans():
    filter_user = request.args.get("user", "").strip() or None
    filter_type = request.args.get("type", "").strip() or None
    date_from   = request.args.get("date_from", "").strip() or None
    date_to     = request.args.get("date_to", "").strip() or None
    page        = request.args.get("page", 1, type=int)
    per_page    = min(request.args.get("per_page", 50, type=int), 500)
    all_reports = get_all_reports(
        limit=per_page,
        date_from=date_from,
        date_to=date_to,
        scan_type=filter_type,
        username=filter_user,
    )
    top_vulns = get_top_vulnerabilities(limit=10)
    return jsonify({
        "reports":   [dict(r) for r in all_reports],
        "top_vulns": list(top_vulns),
    })


@admin_bp.route("/api/admin/scans/<token>", methods=["DELETE"])
@admin_required
def api_admin_delete_scan(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"ok": False, "error": "Invalid token."}), 400
    ok, msg = delete_report(token)
    if ok:
        log_event("scan_deleted", current_user.username, current_user.id,
                  category="admin", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@admin_bp.route("/api/admin/audit")
@admin_required
def api_admin_audit():
    uid       = request.args.get("user_id", type=int)
    category  = request.args.get("category") or None
    action    = request.args.get("action") or None
    date_from = request.args.get("date_from") or None
    date_to   = request.args.get("date_to") or None
    page      = request.args.get("page", 1, type=int)
    per_page  = request.args.get("per_page", 50, type=int)
    logs, total = get_audit_log(user_id=uid, category=category, action=action,
                                date_from=date_from, date_to=date_to,
                                page=page, per_page=per_page)
    return jsonify({"logs": [dict(l) for l in logs], "total": total})


@admin_bp.route("/api/admin/ai/clear-all", methods=["POST"])
@admin_required
def api_admin_ai_clear_all():
    from ai_agent import get_aria
    aria  = get_aria()
    count = aria.clear_all_histories()
    log_event("ai_history_cleared", current_user.username, current_user.id,
              "admin", details=f"Cleared {count} AI conversation sessions")
    return jsonify({"message": f"Cleared {count} AI conversation session(s).", "count": count})


# ════════════════════════════════════════════════════════════════════════════
#  SUBSCRIPTION / PLAN MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════

@admin_bp.route("/api/admin/subscriptions")
@admin_required
def api_admin_subscriptions():
    """List all users with their plan, usage and quota."""
    subs = get_all_subscriptions()
    return jsonify({"subscriptions": subs, "plans": PLANS})


@admin_bp.route("/api/admin/subscriptions/<int:uid>", methods=["PATCH"])
@admin_required
def api_admin_set_subscription(uid):
    """Assign a plan to a user and reset their monthly counter."""
    data       = request.get_json(silent=True) or {}
    plan       = data.get("plan", "free")
    notes      = data.get("notes", "")
    expires_at = data.get("expires_at")
    ok = set_subscription(uid, plan, notes=notes, expires_at=expires_at)
    if not ok:
        return jsonify({"error": f"Plan invalide. Plans disponibles: {list(PLANS)}"}), 400
    log_event("subscription_changed", current_user.username, current_user.id,
              category="admin", resource=f"user:{uid}",
              details=f"plan={plan} expires={expires_at}")
    return jsonify({"ok": True, "uid": uid, "plan": plan})


@admin_bp.route("/api/admin/usage")
@admin_required
def api_admin_usage():
    """Monthly scan usage report per user."""
    return jsonify(get_monthly_usage_report())
