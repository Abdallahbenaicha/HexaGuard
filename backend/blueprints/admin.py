"""SecuraX — admin blueprint.

Handles both HTML admin panel routes (Jinja2) and the JSON admin API
consumed by the React frontend.
"""

import json as _json
import logging
import threading
import time
import urllib.request

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from database import (
    PLANS,
    count_active_admins,
    count_users,
    create_user,
    delete_report,
    get_all_reports,
    get_all_subscriptions,
    get_all_users,
    get_audit_log,
    get_audit_stats,
    get_monthly_usage_report,
    get_system_stats,
    get_top_vulnerabilities,
    get_user_by_id,
    hard_delete_user,
    log_event,
    set_subscription,
    update_user,
)
from extensions import limiter
from forms import check_password_complexity
from utils import _UUID_RE, _normalize_target, admin_required

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
    _page       = request.args.get("page", 1, type=int)  # reserved for future pagination
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
    return jsonify({"logs": [dict(row) for row in logs], "total": total})


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


# ════════════════════════════════════════════════════════════════════════════
#  BUG BOUNTY TARGETS  (arkadiyt/bounty-targets-data)
# ════════════════════════════════════════════════════════════════════════════

_BB_CACHE_TTL   = 3600          # 1 hour
_BB_CACHE_LOCK  = threading.Lock()
_BB_CACHE: dict = {}            # platform → {"data": [...], "ts": float}
_BB_INFLIGHT: set = set()       # Fix 3: single-flight — platforms being fetched right now

_PLATFORM_URLS = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

# ── Scan-policy detection ────────────────────────────────────────────────────
# Terms that EXPLICITLY allow automated scanning
_ALLOW_TERMS = [
    "automated scanning allowed", "automated scanning is allowed",
    "automated testing allowed", "automated tools allowed",
    "automated scanning is permitted", "automated scanning permitted",
    "feel free to use automated", "scanners are allowed",
    "you may use automated", "automated tools are fine",
    "burp suite is allowed", "zap is allowed",
]

# Terms that EXPLICITLY prohibit automated scanning
_BLOCK_TERMS = [
    "no automated scanning", "no automated testing",
    "do not use automated", "do not run automated",
    "automated scanning is prohibited", "automated scanning prohibited",
    "automated tools are not allowed", "automated tools not permitted",
    "manual testing only", "manual only",
    "no scanners", "scanners not allowed", "scanners are not permitted",
    "no vulnerability scanner", "no automated vulnerability",
    "without prior permission", "without written permission",
    "please do not run",
]

# Terms that indicate restrictions (not full block, but not clean either)
_RESTRICT_TERMS = [
    "rate limit", "rate-limit", "rate limiting",
    "no dos", "no denial of service", "no brute force", "no bruteforce",
    "no aggressive", "do not perform dos",
    "avoid high volume", "low and slow",
    "authentication required", "auth required",
    "production only", "no testing on production",
]


def _analyse_policy(text: str | None) -> dict:
    """Return a rich scan-policy dict instead of a binary bool.

    Returns:
        {
            "status":     "ALLOWED" | "RESTRICTED" | "UNKNOWN",
            "confidence": 0-100,
            "signals":    ["+ signal", "- signal"],
        }
    """
    if not text:
        # No instruction at all — we genuinely cannot tell → UNKNOWN
        return {"status": "UNKNOWN", "confidence": 0,
                "signals": ["No automation policy found in program instructions"]}

    lower   = text.lower()
    signals = []
    allow_hits  = [t for t in _ALLOW_TERMS   if t in lower]
    block_hits  = [t for t in _BLOCK_TERMS   if t in lower]
    restrict_hits = [t for t in _RESTRICT_TERMS if t in lower]

    for h in allow_hits:
        signals.append(f"+ {h}")
    for h in block_hits:
        signals.append(f"- {h}")
    for h in restrict_hits:
        signals.append(f"⚠ {h}")

    if block_hits and not allow_hits:
        # Clear prohibition
        confidence = min(95, 60 + len(block_hits) * 15)
        return {"status": "RESTRICTED", "confidence": confidence, "signals": signals}

    if allow_hits and not block_hits:
        # Explicit permission
        confidence = min(95, 60 + len(allow_hits) * 15)
        if restrict_hits:
            # Allowed but with restrictions
            confidence = max(50, confidence - len(restrict_hits) * 10)
            return {"status": "RESTRICTED", "confidence": confidence, "signals": signals}
        return {"status": "ALLOWED", "confidence": confidence, "signals": signals}

    if block_hits and allow_hits:
        # Contradictory — cannot determine
        return {"status": "UNKNOWN", "confidence": 30,
                "signals": signals + ["Contradictory signals — manual review required"]}

    if restrict_hits:
        # Only restrictions, no explicit allow/block
        return {"status": "RESTRICTED", "confidence": 40, "signals": signals}

    # No signals at all — instruction exists but says nothing about automation
    return {"status": "UNKNOWN", "confidence": 20,
            "signals": ["No automation-related terms found in instructions"]}


# Asset types we expose (web-testable)
_WEB_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN", "WEB_APPLICATION"}


def _fetch_platform(platform: str) -> list:
    """Fetch and parse one platform JSON, cached for TTL seconds.
    Single-flight: if another thread is already fetching this platform,
    wait briefly then return cached (or empty) — avoids hammering GitHub.
    """
    # Fast path: return cached data if still fresh
    with _BB_CACHE_LOCK:
        cached = _BB_CACHE.get(platform)
        if cached and (time.time() - cached["ts"]) < _BB_CACHE_TTL:
            return cached["data"]
        # Single-flight guard: if already being fetched, return stale data or []
        if platform in _BB_INFLIGHT:
            return cached["data"] if cached else []
        _BB_INFLIGHT.add(platform)

    try:
        url = _PLATFORM_URLS.get(platform)
        if not url:
            return []
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "HexaGuard/1.0 (bug-bounty-browser)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = _json.loads(resp.read().decode())
        with _BB_CACHE_LOCK:
            _BB_CACHE[platform] = {"data": raw, "ts": time.time()}
        return raw
    except Exception as exc:
        logger.warning("bounty-targets: failed to fetch %s — %s", platform, exc)
        with _BB_CACHE_LOCK:
            cached = _BB_CACHE.get(platform)
        return cached["data"] if cached else []
    finally:
        with _BB_CACHE_LOCK:
            _BB_INFLIGHT.discard(platform)


def _normalise_hackerone(programs: list) -> list:
    out = []
    for prog in programs:
        if prog.get("submission_state") != "open":
            continue
        # Program-level policy text (most reliable for HackerOne)
        prog_policy = prog.get("policy", "") or ""
        for scope_item in prog.get("targets", {}).get("in_scope", []):
            asset_type = scope_item.get("asset_type", "")
            if asset_type not in _WEB_ASSET_TYPES:
                continue
            # Combine scope-level instruction + program policy for analysis
            scope_instr = scope_item.get("instruction") or ""
            combined    = (scope_instr + " " + prog_policy).strip() or None
            policy      = _analyse_policy(combined)
            # Compute max_severity properly
            sev_raw = scope_item.get("max_severity") or ""
            max_sev = sev_raw.lower() if sev_raw else "unknown"
            out.append({
                "platform":         "hackerone",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("handle", ""),
                "program_url":      prog.get("url", ""),
                "website":          prog.get("website", ""),
                "asset":            scope_item.get("asset_identifier", ""),
                "asset_type":       asset_type,
                "max_severity":     max_sev,
                "eligible_bounty":  scope_item.get("eligible_for_bounty", False),
                "scan_policy":      policy,
                # kept for backwards-compat with existing filter logic
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_instr,
                "managed":          prog.get("managed_program", False),
                "avg_response_h":   prog.get("average_time_to_first_program_response"),
            })
    return out


def _normalise_bugcrowd(programs: list) -> list:
    out = []
    for prog in programs:
        if not prog.get("targets"):
            continue
        # Program-level policy: Bugcrowd uses 'safe_harbor' + top-level description
        prog_brief     = prog.get("brief", "") or ""
        prog_extra     = prog.get("target_groups_extra", "") or ""
        prog_policy = (prog_brief + " " + prog_extra).strip() or None
        # Max severity from program level
        rewards = prog.get("rewards", {}) or {}
        if rewards.get("critical"):
            prog_max_sev = "critical"
        elif rewards.get("high"):
            prog_max_sev = "high"
        elif rewards.get("medium"):
            prog_max_sev = "medium"
        else:
            prog_max_sev = "low"
        for scope_item in prog.get("targets", {}).get("in_scope", []):
            asset_type = scope_item.get("type", "")
            if asset_type.lower() not in {"website", "web application", "api", "wildcard"}:
                continue
            # Scope-level description may add more context — combine with program policy
            scope_desc  = scope_item.get("description") or ""
            combined    = (scope_desc + " " + (prog_policy or "")).strip() or None
            policy      = _analyse_policy(combined)
            out.append({
                "platform":         "bugcrowd",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("name", "").lower().replace(" ", "-"),
                "program_url":      prog.get("program_url", ""),
                "website":          scope_item.get("target", ""),
                "asset":            scope_item.get("target", ""),
                "asset_type":       "URL",
                "max_severity":     prog_max_sev,
                "eligible_bounty":  bool(prog.get("max_payout")),
                "scan_policy":      policy,
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_desc,
                "managed":          False,
                "avg_response_h":   None,
            })
    return out


def _normalise_yeswehack(programs: list) -> list:
    out = []
    for prog in programs:
        if not prog.get("scopes"):
            continue
        # Program-level policy for YesWeHack
        prog_policy_text = (prog.get("policy") or prog.get("description") or "").strip() or None
        # Max severity: YesWeHack programs have a 'qualifying_vulnerability' or 'bounty_reward_range'
        reward_grid = prog.get("bounty_reward_range") or {}
        if reward_grid.get("critical"):
            prog_max_sev = "critical"
        elif reward_grid.get("high"):
            prog_max_sev = "high"
        elif reward_grid.get("medium"):
            prog_max_sev = "medium"
        elif prog.get("bounty"):
            prog_max_sev = "low"
        else:
            prog_max_sev = "unknown"
        for scope_item in prog.get("scopes", []):
            scope_type = scope_item.get("scope_type", "")
            if scope_type.lower() not in {"web-application", "api", "ip-address"}:
                continue
            scope_desc = scope_item.get("description") or ""
            combined   = (scope_desc + " " + (prog_policy_text or "")).strip() or None
            policy     = _analyse_policy(combined)
            out.append({
                "platform":         "yeswehack",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("slug", ""),
                "program_url":      f"https://yeswehack.com/programs/{prog.get('slug', '')}",
                "website":          scope_item.get("scope", ""),
                "asset":            scope_item.get("scope", ""),
                "asset_type":       "URL" if scope_type != "ip-address" else "CIDR",
                "max_severity":     prog_max_sev,
                "eligible_bounty":  prog.get("bounty", False),
                "scan_policy":      policy,
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_desc,
                "managed":          False,
                "avg_response_h":   None,
            })
    return out


_NORMALISERS = {
    "hackerone": (_fetch_platform, _normalise_hackerone),
    "bugcrowd":  (_fetch_platform, _normalise_bugcrowd),
    "yeswehack": (_fetch_platform, _normalise_yeswehack),
}


@admin_bp.route("/api/admin/bounty-targets")
@admin_required
def api_bounty_targets():
    """
    Return paginated, filtered list of bug-bounty targets.
    Query params:
      platform   – hackerone | bugcrowd | yeswehack | all   (default: all)
      asset_type – URL | WILDCARD | all                      (default: all)
      bounty     – 1 to show only bounty-eligible             (default: off)
      policy     – ALLOWED | RESTRICTED | UNKNOWN | all      (default: ALLOWED)
      search     – substring match on asset / program name    (default: "")
      page       – 1-indexed                                  (default: 1)
      per_page   – max 100                                    (default: 30)
    """
    platform   = request.args.get("platform", "all").lower()
    asset_type = request.args.get("asset_type", "all").upper()
    bounty     = request.args.get("bounty", "0") == "1"
    # New: policy filter replaces binary auto_only
    policy_filter = request.args.get("policy", "ALLOWED").upper()
    # Legacy compat: auto_only=0 → show all; auto_only=1 → ALLOWED only
    if "auto_only" in request.args and "policy" not in request.args:
        policy_filter = "ALLOWED" if request.args.get("auto_only", "1") != "0" else "ALL"
    search     = request.args.get("search", "").lower().strip()
    page       = max(1, request.args.get("page", 1, type=int))
    per_page   = min(100, max(1, request.args.get("per_page", 30, type=int)))

    platforms = list(_NORMALISERS) if platform == "all" else [platform]
    all_targets: list = []

    for plat in platforms:
        if plat not in _NORMALISERS:
            continue
        fetch_fn, norm_fn = _NORMALISERS[plat]
        raw = fetch_fn(plat)
        all_targets.extend(norm_fn(raw))

    # --- Filter ---
    if policy_filter != "ALL":
        all_targets = [t for t in all_targets
                       if t["scan_policy"]["status"] == policy_filter]
    if bounty:
        all_targets = [t for t in all_targets if t["eligible_bounty"]]
    if asset_type != "ALL":
        all_targets = [t for t in all_targets if t["asset_type"] == asset_type]
    if search:
        all_targets = [
            t for t in all_targets
            if search in t["asset"].lower() or search in t["program_name"].lower()
        ]

    total   = len(all_targets)
    start   = (page - 1) * per_page
    targets = all_targets[start: start + per_page]

    # Cache ages
    cache_info = {}
    for plat in platforms:
        cached = _BB_CACHE.get(plat)
        if cached:
            age = int(time.time() - cached["ts"])
            cache_info[plat] = {"age_seconds": age, "expires_in": max(0, _BB_CACHE_TTL - age)}
        else:
            cache_info[plat] = {"age_seconds": None, "expires_in": 0}

    return jsonify({
        "targets":    targets,
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "pages":      max(1, -(-total // per_page)),   # ceil division
        "cache_info": cache_info,
    })


@admin_bp.route("/api/admin/bounty-targets/refresh", methods=["POST"])
@admin_required
def api_bounty_targets_refresh():
    """Force-invalidate the in-memory cache for all platforms."""
    with _BB_CACHE_LOCK:
        _BB_CACHE.clear()
    log_event("bounty_cache_refresh", current_user.username, current_user.id,
              category="admin", status="success")
    return jsonify({"ok": True, "message": "Cache cleared — data will be re-fetched on next request."})


@admin_bp.route("/api/admin/bounty-targets/stats")
@admin_required
def api_bounty_targets_stats():
    """Return high-level stats (totals per platform) without pagination."""
    stats = {}
    for plat in _NORMALISERS:
        fetch_fn, norm_fn = _NORMALISERS[plat]
        raw     = fetch_fn(plat)
        targets = norm_fn(raw)
        allowed     = [t for t in targets if t["scan_policy"]["status"] == "ALLOWED"]
        restricted  = [t for t in targets if t["scan_policy"]["status"] == "RESTRICTED"]
        unknown     = [t for t in targets if t["scan_policy"]["status"] == "UNKNOWN"]
        bounty_list = [t for t in allowed  if t["eligible_bounty"]]
        stats[plat] = {
            "total":        len(targets),
            "allowed":      len(allowed),
            "restricted":   len(restricted),
            "unknown":      len(unknown),
            # kept for backwards compat
            "auto_ok":      len(allowed),
            "with_bounty":  len(bounty_list),
        }
    return jsonify({"stats": stats})
