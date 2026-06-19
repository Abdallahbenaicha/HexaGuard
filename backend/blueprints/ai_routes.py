"""SecurAx — AI routes blueprint (ARIA agent endpoints)."""

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from ai_agent import get_aria
from extensions import limiter
from utils import _UUID_RE, require_permission
from database import get_report, log_event

logger = logging.getLogger(__name__)

ai_bp = Blueprint("ai", __name__)


@ai_bp.route("/api/ai/analyze", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("20/minute")
def ai_analyze():
    data      = request.get_json(silent=True) or {}
    findings  = data.get("findings", [])
    target    = data.get("target", "unknown")
    scan_type = data.get("scan_type", "web")

    # report.html sends a token — load findings from DB
    token = (data.get("token") or "").strip()
    if token and not findings:
        if not _UUID_RE.match(token):
            return jsonify({"error": "رمز التقرير غير صالح."}), 400
        report_data = get_report(token)
        if not report_data:
            return jsonify({"error": "التقرير غير موجود."}), 404
        if report_data.get("user_id") != current_user.id and current_user.role != "admin":
            log_event("idor_attempt", current_user.username, current_user.id,
                      category="security", resource=f"/api/ai/analyze/{token}",
                      ip_address=request.remote_addr, status="blocked")
            return jsonify({"error": "هذا التقرير لا يخصّك."}), 403
        result    = report_data.get("result", {})
        findings  = result.get("vulnerabilities", [])
        target    = result.get("target", "unknown")
        scan_type = result.get("scan_type", "web")

    if not findings:
        return jsonify({"error": "No findings to analyze."}), 400
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list."}), 400
    if len(findings) > 500:
        return jsonify({"error": "findings list exceeds maximum of 500 items."}), 400
    findings = [f for f in findings if isinstance(f, dict)]
    if not findings:
        return jsonify({"error": "findings must contain dict objects."}), 400

    aria     = get_aria()
    analysis = aria.analyze_findings(findings, target, scan_type)
    return jsonify({"analysis": analysis})


@ai_bp.route("/api/ai/chat", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def ai_chat():
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    context = data.get("context", {})

    if not message:
        return jsonify({"error": "Empty message."}), 400
    if len(message) > 4000:
        return jsonify({"error": "Message too long (max 4000 chars)."}), 400

    try:
        aria  = get_aria()
        reply = aria.chat(message, context, user_id=str(current_user.id))
        return jsonify({
            "reply":    reply,
            "provider": aria.provider,
            "ai_mode":  "online" if aria.ai_active else "offline",
        })
    except Exception as exc:
        logger.exception("ai_chat error")
        return jsonify({
            "reply":    f"⚠️ AI error: {exc}",
            "provider": "offline",
            "ai_mode":  "offline",
        }), 200


@ai_bp.route("/api/ai/fix", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("10/minute")
def ai_fix():
    data      = request.get_json(silent=True) or {}
    vuln_type = (data.get("vuln_type") or "").strip()
    context   = data.get("context", {})
    if not vuln_type:
        return jsonify({"error": "vuln_type required."}), 400
    aria = get_aria()
    fix  = aria.generate_fix(vuln_type, context)
    return jsonify({"fix": fix})


@ai_bp.route("/api/ai/history/clear", methods=["POST"])
@login_required
def ai_history_clear():
    aria = get_aria()
    aria.clear_history(str(current_user.id))
    return jsonify({"ok": True, "message": "Conversation history cleared."})


@ai_bp.route("/api/ai/status")
@login_required
def ai_status():
    aria = get_aria()
    return jsonify({
        "status":   "online" if aria.ai_active else "offline",
        "model":    getattr(aria, "_model_name", "gemini-2.0-flash"),
        "provider": getattr(aria, "provider", "unknown"),
    })


# ── Compatibility bridges (React calls /api/chat and /api/analyze_findings) ──

@ai_bp.route("/api/analyze_findings", methods=["POST"])
@login_required
@limiter.limit("20/minute")
def analyze_findings_bridge():
    """Bridge: React /api/analyze_findings → ARIA AI analyze."""
    data      = request.get_json(silent=True) or {}
    findings  = data.get("findings", [])
    target    = data.get("target", "unknown")
    scan_type = data.get("scan_type", "web")
    if not findings:
        return jsonify({"analysis": "No findings to analyze."}), 200
    try:
        aria     = get_aria()
        analysis = aria.analyze_findings(findings, target, scan_type)
        return jsonify({"analysis": analysis})
    except Exception as exc:
        logger.exception("analyze_findings_bridge error")
        return jsonify({"analysis": f"AI analysis error: {exc}"}), 200


@ai_bp.route("/api/chat", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def chat_bridge():
    """Bridge: React /api/chat → ARIA AI chat."""
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    context = data.get("context", {})
    if not message:
        return jsonify({"response": "Empty message."}), 400
    try:
        aria  = get_aria()
        reply = aria.chat(message, context, user_id=str(current_user.id))
        return jsonify({"response": reply})
    except Exception as exc:
        logger.exception("chat_bridge error")
        return jsonify({"response": f"AI error: {exc}"}), 200
