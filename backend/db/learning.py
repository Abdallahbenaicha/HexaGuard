"""HexaGuard Learning System Database Module (db/learning.py).

Implements:
- Exercise management (learning_exercises)
- Attempt tracking (exercise_attempts) with Rule C (INTRODUCED engagement state)
- Backend-only keyword coverage auto-evaluator (evaluate_assessment_submission - D-07)
- Dual-layer attempt ownership checks (D-06)
- Atomic ARIA budget incrementation (D-05)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from db.connection import _get_db
    from db.skills import record_capability_evidence, compute_mastery_matrix
except ImportError:
    from backend.db.connection import _get_db
    from backend.db.skills import record_capability_evidence, compute_mastery_matrix

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Auto-Evaluator (D-07 Backend Only) ─────────────────────────────────────────

def evaluate_assessment_submission(
    submission_text: str,
    content_json: dict | str | None,
) -> tuple[float, str]:
    """Backend-only keyword evaluation for assessment exercises.

    CRITICAL (Rule D / D-07):
    Client NEVER provides score or evaluation_status.
    Max score is 0.9 (score 1.0 is strictly reserved for VERIFIED server-side events).
    """
    if isinstance(content_json, str):
        try:
            content = json.loads(content_json)
        except Exception:
            content = {}
    elif isinstance(content_json, dict):
        content = content_json
    else:
        content = {}

    expected_concepts: list[str] = content.get("expected_concepts", [])
    min_words: int = content.get("min_words", 50)

    words = submission_text.strip().split() if submission_text else []
    word_count = len(words)
    if word_count < min_words:
        return (0.2, f"Insufficient depth: {word_count}/{min_words} words")

    if not expected_concepts:
        return (0.6, "No specific concepts required; minimum length met")

    text_lower = submission_text.lower()
    covered = sum(1 for c in expected_concepts if c.lower() in text_lower)
    coverage_ratio = covered / len(expected_concepts)

    # Score range: 0.3 (no concepts covered) to 0.9 (all covered) — capped at 0.9
    score = round(min(0.9, 0.3 + (coverage_ratio * 0.6)), 2)
    return (score, f"Covered {covered}/{len(expected_concepts)} expected concepts")


# ── Exercise CRUD ─────────────────────────────────────────────────────────────

def create_exercise(
    vuln_type: str,
    capability: str,
    exercise_type: str,
    title_en: str,
    description_en: Optional[str] = None,
    difficulty: str = "medium",
    content_json: Optional[dict | str] = None,
    cert_hint: Optional[str] = None,
    is_active: int = 1,
) -> dict[str, Any]:
    """Create a new learning exercise in learning_exercises table."""
    db = _get_db()
    now = _utcnow_iso()
    raw_content = json.dumps(content_json) if isinstance(content_json, dict) else content_json

    cur = db.execute(
        "INSERT INTO learning_exercises "
        "(vuln_type, capability, exercise_type, title_en, description_en, difficulty, content_json, cert_hint, is_active, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (vuln_type, capability, exercise_type, title_en, description_en, difficulty, raw_content, cert_hint, is_active, now),
    )
    db.commit()
    ex_id = getattr(cur, "lastrowid", None)
    return {
        "id": ex_id,
        "vuln_type": vuln_type,
        "capability": capability,
        "exercise_type": exercise_type,
        "title_en": title_en,
        "description_en": description_en,
        "difficulty": difficulty,
        "content_json": raw_content,
        "cert_hint": cert_hint,
        "is_active": is_active,
        "created_at": now,
    }


def get_exercise(exercise_id: int) -> dict[str, Any] | None:
    """Retrieve an exercise by its ID."""
    db = _get_db()
    row = db.execute(
        "SELECT id, vuln_type, capability, exercise_type, title_en, description_en, "
        "difficulty, content_json, cert_hint, is_active, created_at "
        "FROM learning_exercises WHERE id = ?",
        (exercise_id,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("content_json") and isinstance(d["content_json"], str):
        try:
            d["content"] = json.loads(d["content_json"])
        except Exception:
            d["content"] = {}
    else:
        d["content"] = {}
    return d


def get_exercises_for_skill(
    vuln_type: str,
    capability: Optional[str] = None,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    """Retrieve all exercises for a vulnerability type and optional capability."""
    db = _get_db()
    sql = (
        "SELECT id, vuln_type, capability, exercise_type, title_en, description_en, "
        "difficulty, content_json, cert_hint, is_active, created_at "
        "FROM learning_exercises WHERE vuln_type = ?"
    )
    params: list[Any] = [vuln_type]
    if capability:
        sql += " AND capability = ?"
        params.append(capability)
    if active_only:
        sql += " AND is_active = 1"
    sql += " ORDER BY id ASC"

    rows = db.execute(sql, tuple(params)).fetchall()
    exercises = []
    for r in rows:
        d = dict(r)
        if d.get("content_json") and isinstance(d["content_json"], str):
            try:
                d["content"] = json.loads(d["content_json"])
            except Exception:
                d["content"] = {}
        else:
            d["content"] = {}
        exercises.append(d)
    return exercises


# ── Attempt CRUD & Evaluation ─────────────────────────────────────────────────

def start_exercise_attempt(user_id: int, exercise_id: int) -> dict[str, Any]:
    """Starts an exercise attempt.

    Rule C: Creates an exercise_attempts record with started_at set.
    This advances the capability to INTRODUCED (engagement state only, zero evidence weight).
    """
    db = _get_db()
    exercise = get_exercise(exercise_id)
    if not exercise:
        raise ValueError(f"Exercise {exercise_id} not found")

    # Determine attempt number
    count_row = db.execute(
        "SELECT COUNT(*) as cnt FROM exercise_attempts WHERE user_id = ? AND exercise_id = ?",
        (user_id, exercise_id),
    ).fetchone()
    attempt_num = (count_row["cnt"] if count_row else 0) + 1

    now = _utcnow_iso()
    cur = db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, "
        "result, evaluation_status, hints_used, aria_calls_used, solution_viewed) "
        "VALUES (?, ?, ?, ?, ?, ?, 'pending', 'pending', 0, 0, 0)",
        (user_id, exercise_id, exercise["vuln_type"], exercise["capability"], attempt_num, now),
    )
    db.commit()
    att_id = getattr(cur, "lastrowid", None)
    return {
        "id": att_id,
        "user_id": user_id,
        "exercise_id": exercise_id,
        "vuln_type": exercise["vuln_type"],
        "capability": exercise["capability"],
        "attempt_number": attempt_num,
        "started_at": now,
        "completed_at": None,
        "submission_text": None,
        "score": None,
        "result": "pending",
        "evaluation_status": "pending",
        "hints_used": 0,
        "aria_calls_used": 0,
        "solution_viewed": 0,
        "evidence_id": None,
    }


def get_attempt(attempt_id: int) -> dict[str, Any] | None:
    """Retrieve an attempt by its ID."""
    db = _get_db()
    row = db.execute(
        "SELECT id, user_id, exercise_id, vuln_type, capability, attempt_number, "
        "started_at, completed_at, submission_text, score, hints_used, aria_calls_used, "
        "solution_viewed, result, evaluation_status, evidence_id "
        "FROM exercise_attempts WHERE id = ?",
        (attempt_id,),
    ).fetchone()
    return dict(row) if row else None


def get_attempt_with_ownership_check(attempt_id: int, user_id: int) -> dict[str, Any] | None:
    """Retrieve an attempt with strict ownership validation (D-06)."""
    attempt = get_attempt(attempt_id)
    if not attempt or attempt["user_id"] != user_id:
        return None
    return attempt


def complete_exercise_attempt(
    attempt_id: int,
    user_id: int,
    submission_text: str = "",
) -> dict[str, Any]:
    """Completes an exercise attempt with backend evaluation.

    CRITICAL (Rule D / D-07):
    - Client CANNOT submit score or evaluation_status.
    - Assessment score is computed server-side via evaluate_assessment_submission().
    - If score >= 0.5, writes skill_capability_evidence with is_verified=0 (EVALUATED).
    """
    db = _get_db()
    attempt = get_attempt_with_ownership_check(attempt_id, user_id)
    if not attempt:
        raise PermissionError("Attempt not found or unauthorized")

    if attempt["completed_at"] is not None:
        raise ValueError("This exercise attempt is already completed")

    exercise = get_exercise(attempt["exercise_id"])
    if not exercise:
        raise ValueError(f"Exercise {attempt['exercise_id']} not found")

    now = _utcnow_iso()
    ex_type = exercise.get("exercise_type", "assessment")
    score: Optional[float] = None
    evaluation_status = "pending"
    result = "pending"
    notes = ""
    evidence_id: Optional[int] = None

    if ex_type == "assessment":
        score, notes = evaluate_assessment_submission(
            submission_text=submission_text,
            content_json=exercise.get("content_json"),
        )
        evaluation_status = "auto_evaluated"
        result = "passed" if score >= 0.5 else "failed"

        # If score qualifies (>= 0.5), record EVALUATED capability evidence
        if score >= 0.5:
            ev = record_capability_evidence(
                user_id=user_id,
                vuln_type=attempt["vuln_type"],
                capability=attempt["capability"],
                evidence_type="EVALUATED",
                evidence_source=f"exercise_attempt:{attempt_id}",
                source_id=str(attempt_id),
                is_verified=0,
                score=score,
                notes=f"Auto-evaluated assessment submission: {notes}",
            )
            evidence_id = ev.get("id")

    elif ex_type == "lab":
        # Lab exercises are scored via server-side sandbox flag verification
        # If flag was already verified, score is 1.0, otherwise pending
        score = attempt.get("score")
        evaluation_status = attempt.get("evaluation_status", "pending")
        result = "passed" if (score and score >= 0.8) else "pending"
    else:
        # manual_task, reporting, scenario: pending human review
        evaluation_status = "pending"
        result = "pending"

    # Update attempt row
    db.execute(
        "UPDATE exercise_attempts "
        "SET completed_at = ?, submission_text = ?, score = ?, result = ?, "
        "evaluation_status = ?, evidence_id = ? "
        "WHERE id = ? AND user_id = ?",
        (now, submission_text, score, result, evaluation_status, evidence_id, attempt_id, user_id),
    )
    db.commit()

    updated_attempt = get_attempt(attempt_id)
    # Compute current capability mastery matrix for response
    matrix = compute_mastery_matrix(user_id, attempt["vuln_type"])

    return {
        "ok": True,
        "attempt": updated_attempt,
        "score": score,
        "evaluation_status": evaluation_status,
        "result": result,
        "notes": notes,
        "mastery": matrix,
    }


# ── ARIA Atomic Call Budget (D-05 / D-06) ──────────────────────────────────────

def increment_attempt_aria_calls_atomic(
    attempt_id: int,
    budget: int = 5,
) -> tuple[bool, int]:
    """Atomically increments ARIA calls used for an attempt, guarded by budget.

    D-05: Single atomic SQL UPDATE with `WHERE aria_calls_used < budget`.
    Returns: (allowed: bool, current_used: int)
    """
    db = _get_db()
    cur = db.execute(
        "UPDATE exercise_attempts "
        "SET aria_calls_used = aria_calls_used + 1 "
        "WHERE id = ? AND aria_calls_used < ?",
        (attempt_id, budget),
    )
    affected = getattr(cur, "rowcount", 0)
    db.commit()

    # Query current count
    row = db.execute(
        "SELECT aria_calls_used FROM exercise_attempts WHERE id = ?",
        (attempt_id,),
    ).fetchone()
    used = row["aria_calls_used"] if row else budget

    if affected > 0:
        return True, used
    return False, used


def mark_attempt_solution_viewed(attempt_id: int) -> None:
    """Sets solution_viewed = 1 on an attempt."""
    db = _get_db()
    db.execute(
        "UPDATE exercise_attempts SET solution_viewed = 1 WHERE id = ?",
        (attempt_id,),
    )
    db.commit()
