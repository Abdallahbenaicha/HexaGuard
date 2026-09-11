"""SecuraX — Skill Ledger Blueprint (Part 0).

Provides:
  - GET  /api/skill/ledger: Full ledger for current authenticated user.
  - GET  /api/skill/taxonomy: Full platform vulnerability taxonomy and metadata.
  - POST /api/skill/self-report: User declares manual study or practice (self-reported).

Security & Integrity Guarantee:
  - Direct user requests CANNOT set status='practiced_verified'.
  - Any request attempting to force 'practiced_verified' via API is strictly rejected (403 Forbidden).
  - 'practiced_verified' can only be earned internally via Sandbox proof completion (Part 1).
"""

from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from database import get_user_skill_ledger, record_skill_progress
from vuln_taxonomy import VULN_TAXONOMY, SCANNERS

logger = logging.getLogger(__name__)

skill_bp = Blueprint("skill", __name__, url_prefix="/api/skill")


@skill_bp.route("/ledger", methods=["GET"])
@login_required
def get_ledger():
    """Retrieve skill ledger for current user."""
    try:
        user_id = current_user.id
        ledger = get_user_skill_ledger(user_id)
        
        # Calculate summary statistics
        counts = {"theory_only": 0, "practiced_self_reported": 0, "practiced_verified": 0}
        for item in ledger:
            st = item.get("status", "theory_only")
            if st in counts:
                counts[st] += 1

        return jsonify({
            "ok": True,
            "user_id": user_id,
            "ledger": ledger,
            "summary": {
                "total_skills": len(ledger),
                "theory_only": counts["theory_only"],
                "practiced_self_reported": counts["practiced_self_reported"],
                "practiced_verified": counts["practiced_verified"],
                "coverage_pct": round(((counts["practiced_self_reported"] + counts["practiced_verified"]) / max(1, len(ledger))) * 100, 1),
                "verified_pct": round((counts["practiced_verified"] / max(1, len(ledger))) * 100, 1),
            },
        }), 200
    except Exception as exc:
        logger.error("Error fetching skill ledger: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": "Failed to retrieve skill ledger"}), 500


@skill_bp.route("/taxonomy", methods=["GET"])
def get_taxonomy_route():
    """Return platform canonical taxonomy and scanner definitions."""
    return jsonify({
        "ok": True,
        "taxonomy": VULN_TAXONOMY,
        "scanners": SCANNERS,
        "total": len(VULN_TAXONOMY),
    }), 200


@skill_bp.route("/self-report", methods=["POST"])
@login_required
def self_report_skill():
    """Record self-reported practice on a vulnerability type.

    REJECTS any attempt to pass status='practiced_verified'.
    """
    data = request.get_json(silent=True) or {}
    vuln_type = str(data.get("vuln_type", "")).strip().lower()
    notes = str(data.get("notes", "")).strip()
    requested_status = str(data.get("status", "")).strip().lower()

    # Reject unauthorized attempts to bypass verification
    if requested_status == "practiced_verified":
        logger.warning(
            "User %s attempted to self-assign 'practiced_verified' on %s. REJECTED.",
            current_user.id, vuln_type,
        )
        return jsonify({
            "ok": False,
            "error": "Forbidden: 'practiced_verified' status cannot be self-reported. It requires verified sandbox proof.",
            "code": "VERIFICATION_BYPASS_FORBIDDEN",
        }), 403

    if not vuln_type or vuln_type not in VULN_TAXONOMY:
        return jsonify({
            "ok": False,
            "error": f"Invalid or unknown vuln_type: '{vuln_type}'",
        }), 400

    try:
        updated = record_skill_progress(
            user_id=current_user.id,
            vuln_type=vuln_type,
            status="practiced_self_reported",
            evidence_ref=f"self_report:{notes[:100]}" if notes else "self_report",
        )
        return jsonify({
            "ok": True,
            "message": f"Successfully recorded self-reported practice for {vuln_type}",
            "entry": updated,
        }), 200
    except Exception as exc:
        logger.error("Error recording self-reported skill: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": str(exc)}), 500


@skill_bp.route("/evidence/<vuln_type>", methods=["GET"])
@login_required
def get_skill_evidence(vuln_type: str):
    """Retrieve capability evidence for a specific vulnerability type."""
    from database import get_capability_evidence
    capability = request.args.get("capability")
    evidence = get_capability_evidence(
        user_id=current_user.id,
        vuln_type=vuln_type,
        capability=capability,
    )
    return jsonify({
        "ok": True,
        "vuln_type": vuln_type,
        "evidence": evidence,
        "count": len(evidence),
    }), 200


@skill_bp.route("/mastery/<vuln_type>", methods=["GET"])
@login_required
def get_skill_mastery(vuln_type: str):
    """Retrieve capability mastery matrix for a specific vulnerability type."""
    from database import compute_mastery_matrix
    matrix = compute_mastery_matrix(user_id=current_user.id, vuln_type=vuln_type)
    return jsonify({
        "ok": True,
        "matrix": matrix,
    }), 200
