"""HexaGuard Learning Blueprint (backend/blueprints/learning.py).

Exposes REST APIs for:
- Listing exercises by vuln_type/capability: GET /api/learning/exercises/<vuln_type>
- Starting exercise attempts: POST /api/learning/attempt/start
- Completing exercise attempts: POST /api/learning/attempt/complete (D-07: backend evaluates, client cannot supply score)
- Fetching user capability mastery matrix: GET /api/learning/mastery/<vuln_type>
- Fetching user capability evidence: GET /api/learning/evidence/<vuln_type>
"""

from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

try:
    from db.learning import (
        create_exercise,
        get_exercise,
        get_exercises_for_skill,
        start_exercise_attempt,
        get_attempt,
        get_attempt_with_ownership_check,
        complete_exercise_attempt,
    )
    from db.skills import (
        compute_mastery_matrix,
        get_capability_evidence,
    )
except ImportError:
    from backend.db.learning import (
        create_exercise,
        get_exercise,
        get_exercises_for_skill,
        start_exercise_attempt,
        get_attempt,
        get_attempt_with_ownership_check,
        complete_exercise_attempt,
    )
    from backend.db.skills import (
        compute_mastery_matrix,
        get_capability_evidence,
    )

logger = logging.getLogger(__name__)

learning_bp = Blueprint("learning", __name__)


@learning_bp.route("/api/learning/exercises/<vuln_type>", methods=["GET"])
def api_get_exercises(vuln_type: str):
    """Retrieve all available exercises for a vulnerability type."""
    capability = request.args.get("capability")
    exercises = get_exercises_for_skill(vuln_type=vuln_type, capability=capability, active_only=True)
    return jsonify({
        "ok": True,
        "vuln_type": vuln_type,
        "capability": capability,
        "exercises": exercises,
        "count": len(exercises),
    })


@learning_bp.route("/api/learning/attempt/start", methods=["POST"])
@login_required
def api_start_attempt():
    """Start an exercise attempt (Rule C: advances INTRODUCED state only)."""
    data = request.get_json(silent=True) or {}
    exercise_id = data.get("exercise_id")
    if not exercise_id:
        return jsonify({"ok": False, "error": "exercise_id is required."}), 400

    try:
        attempt = start_exercise_attempt(user_id=current_user.id, exercise_id=int(exercise_id))
        return jsonify({
            "ok": True,
            "attempt": attempt,
            "message": "Exercise attempt started.",
        }), 201
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as exc:
        logger.error("Failed to start exercise attempt: %s", exc)
        return jsonify({"ok": False, "error": "Failed to start exercise attempt."}), 500


@learning_bp.route("/api/learning/attempt/complete", methods=["POST"])
@login_required
def api_complete_attempt():
    """Complete an exercise attempt with backend-only evaluation.

    CRITICAL (Rule D / D-07):
    Client submits attempt_id and submission_text only.
    Any client-supplied score, evaluation_status, or is_verified fields are ignored.
    """
    data = request.get_json(silent=True) or {}
    attempt_id = data.get("attempt_id")
    if not attempt_id:
        return jsonify({"ok": False, "error": "attempt_id is required."}), 400

    submission_text = str(data.get("submission_text", "")).strip()

    try:
        res = complete_exercise_attempt(
            attempt_id=int(attempt_id),
            user_id=current_user.id,
            submission_text=submission_text,
        )
        return jsonify(res), 200
    except PermissionError:
        return jsonify({"ok": False, "error": "Attempt not found or access denied."}), 403
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as exc:
        logger.error("Failed to complete exercise attempt: %s", exc)
        return jsonify({"ok": False, "error": "Failed to complete attempt."}), 500


@learning_bp.route("/api/learning/mastery/<vuln_type>", methods=["GET"])
@login_required
def api_get_mastery(vuln_type: str):
    """Retrieve capability mastery matrix for a specific vulnerability type."""
    matrix = compute_mastery_matrix(user_id=current_user.id, vuln_type=vuln_type)
    return jsonify({
        "ok": True,
        "matrix": matrix,
    })


@learning_bp.route("/api/learning/evidence/<vuln_type>", methods=["GET"])
@login_required
def api_get_evidence(vuln_type: str):
    """Retrieve evidence entries for a specific vulnerability type."""
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
    })
