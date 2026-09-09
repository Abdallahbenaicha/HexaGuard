"""SecuraX Database Module — Skill Ledger & Shadow Manual Tasks (v1).

Manages user skill progression (Skill Ledger) and post-scan manual hunting
lessons (Shadow Manual Tasks).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from db.connection import _get_db, _norm
except ImportError:
    from backend.db.connection import _get_db, _norm

try:
    from vuln_taxonomy import VULN_TAXONOMY
except ImportError:
    from backend.vuln_taxonomy import VULN_TAXONOMY

logger = logging.getLogger(__name__)

VALID_SKILL_STATUSES = {
    "theory_only",
    "practiced_self_reported",
    "practiced_verified",
}

STATUS_HIERARCHY = {
    "theory_only": 0,
    "practiced_self_reported": 1,
    "practiced_verified": 2,
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_user_skill_ledger(user_id: int) -> list[dict[str, Any]]:
    """Retrieve full skill ledger for a user across all canonical vuln_types.

    Categories with no practice recorded in DB are returned with default 'theory_only'.
    """
    db = _get_db()
    rows = db.execute(
        "SELECT vuln_type, status, evidence_ref, attempts_count, last_practiced_at, created_at, updated_at "
        "FROM skill_ledger WHERE user_id = ?",
        (int(user_id),),
    ).fetchall()

    recorded: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = _norm(r)
        recorded[d["vuln_type"]] = d

    results: list[dict[str, Any]] = []
    for v_id, meta in VULN_TAXONOMY.items():
        if v_id in recorded:
            entry = recorded[v_id]
            results.append({
                "vuln_type": v_id,
                "name_en": meta["name_en"],
                "name_ar": meta["name_ar"],
                "scanner": meta["scanner"],
                "difficulty": meta["difficulty"],
                "severity_default": meta.get("severity_default", "medium"),
                "status": entry.get("status", "theory_only"),
                "evidence_ref": entry.get("evidence_ref") or "",
                "attempts_count": entry.get("attempts_count", 0),
                "last_practiced_at": entry.get("last_practiced_at"),
                "is_dataset_type": v_id in VULN_TAXONOMY,
            })
        else:
            results.append({
                "vuln_type": v_id,
                "name_en": meta["name_en"],
                "name_ar": meta["name_ar"],
                "scanner": meta["scanner"],
                "difficulty": meta["difficulty"],
                "severity_default": meta.get("severity_default", "medium"),
                "status": "theory_only",
                "evidence_ref": "",
                "attempts_count": 0,
                "last_practiced_at": None,
                "is_dataset_type": True,
            })

    return results


def record_skill_progress(
    user_id: int,
    vuln_type: str,
    status: str,
    evidence_ref: str = "",
) -> dict[str, Any]:
    """Internal updater for skill ledger.

    Strict rules:
      - Validates vuln_type against VULN_TAXONOMY.
      - Validates status in VALID_SKILL_STATUSES.
      - Never downgrades 'practiced_verified' to 'practiced_self_reported'.
      - Increments attempts_count and refreshes last_practiced_at.
    """
    v_canon = (vuln_type or "").strip().lower()
    if v_canon not in VULN_TAXONOMY:
        raise ValueError(f"Unknown vuln_type '{vuln_type}' not in canonical taxonomy.")

    s_canon = (status or "").strip().lower()
    if s_canon not in VALID_SKILL_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of {VALID_SKILL_STATUSES}.")

    now = _utcnow_iso()
    db = _get_db()

    existing = db.execute(
        "SELECT id, status, attempts_count FROM skill_ledger WHERE user_id = ? AND vuln_type = ?",
        (int(user_id), v_canon),
    ).fetchone()

    if existing:
        ex_dict = _norm(existing)
        current_status = ex_dict.get("status", "theory_only")
        curr_lvl = STATUS_HIERARCHY.get(current_status, 0)
        new_lvl = STATUS_HIERARCHY.get(s_canon, 0)

        # Retain higher status (never downgrade verified to self-reported)
        final_status = current_status if curr_lvl > new_lvl else s_canon
        new_attempts = int(ex_dict.get("attempts_count", 0)) + 1

        db.execute(
            "UPDATE skill_ledger SET status = ?, evidence_ref = ?, attempts_count = ?, "
            "last_practiced_at = ?, updated_at = ? WHERE user_id = ? AND vuln_type = ?",
            (final_status, evidence_ref, new_attempts, now, now, int(user_id), v_canon),
        )
        db.commit()
        return {
            "user_id": int(user_id),
            "vuln_type": v_canon,
            "status": final_status,
            "evidence_ref": evidence_ref,
            "attempts_count": new_attempts,
            "last_practiced_at": now,
        }
    else:
        db.execute(
            "INSERT INTO skill_ledger (user_id, vuln_type, status, evidence_ref, attempts_count, "
            "last_practiced_at, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            (int(user_id), v_canon, s_canon, evidence_ref, now, now, now),
        )
        db.commit()
        return {
            "user_id": int(user_id),
            "vuln_type": v_canon,
            "status": s_canon,
            "evidence_ref": evidence_ref,
            "attempts_count": 1,
            "last_practiced_at": now,
        }


# ── Shadow Manual Tasks DB Helpers (for Part 2 & Part 3) ──────────────────────────

def create_shadow_tasks_for_report(
    report_token: str,
    user_id: Optional[int],
    vuln_types: list[str],
) -> list[dict[str, Any]]:
    """Create pending shadow manual tasks for unique vuln_types discovered in a report."""
    if not report_token or not vuln_types:
        return []

    db = _get_db()
    now = _utcnow_iso()
    created = []

    unique_types = sorted(list(set(vt.strip().lower() for vt in vuln_types if vt.strip().lower() in VULN_TAXONOMY)))
    for vt in unique_types:
        try:
            # Check if task already exists for this report + vuln_type
            existing = db.execute(
                "SELECT id, status FROM shadow_manual_tasks WHERE report_token = ? AND vuln_type = ?",
                (report_token, vt),
            ).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO shadow_manual_tasks (report_token, user_id, vuln_type, status, created_at) "
                    "VALUES (?, ?, ?, 'pending', ?)",
                    (report_token, user_id, vt, now),
                )
                created.append(vt)
        except Exception as exc:
            logger.warning("Could not insert shadow task for %s / %s: %s", report_token, vt, exc)

    db.commit()
    return created


def get_shadow_tasks_for_report(report_token: str) -> list[dict[str, Any]]:
    """Get all shadow manual tasks generated by a specific scan report."""
    db = _get_db()
    rows = db.execute(
        "SELECT id, report_token, user_id, vuln_type, status, notes, created_at, updated_at "
        "FROM shadow_manual_tasks WHERE report_token = ? ORDER BY id ASC",
        (report_token,),
    ).fetchall()

    tasks = []
    for r in rows:
        d = _norm(r)
        vt = d["vuln_type"]
        meta = VULN_TAXONOMY.get(vt, {})
        d["meta"] = {
            "name_en": meta.get("name_en", vt),
            "name_ar": meta.get("name_ar", vt),
            "scanner": meta.get("scanner", "web"),
            "difficulty": meta.get("difficulty", "medium"),
            "owasp": meta.get("owasp"),
            "portswigger": meta.get("portswigger"),
        }
        tasks.append(d)
    return tasks


def get_user_shadow_backlog(user_id: int) -> list[dict[str, Any]]:
    """Retrieve all pending shadow manual tasks for a user, oldest first."""
    db = _get_db()
    rows = db.execute(
        "SELECT sm.id, sm.report_token, sm.user_id, sm.vuln_type, sm.status, sm.created_at, "
        "sr.target, sr.scan_type "
        "FROM shadow_manual_tasks sm "
        "LEFT JOIN scan_reports sr ON sm.report_token = sr.token "
        "WHERE (sm.user_id = ? OR sr.user_id = ?) AND sm.status = 'pending' "
        "ORDER BY sm.created_at ASC, sm.id ASC",
        (int(user_id), int(user_id)),
    ).fetchall()

    backlog = []
    seen = set()
    for r in rows:
        d = _norm(r)
        vt = d["vuln_type"]
        if vt in seen:
            continue
        seen.add(vt)
        meta = VULN_TAXONOMY.get(vt, {})
        d["meta"] = {
            "name_en": meta.get("name_en", vt),
            "name_ar": meta.get("name_ar", vt),
            "scanner": meta.get("scanner", "web"),
            "difficulty": meta.get("difficulty", "medium"),
        }
        backlog.append(d)
    return backlog


def complete_shadow_task(
    report_token: str,
    vuln_type: str,
    user_id: int,
    notes: str = "",
    verified: bool = False,
) -> dict[str, Any]:
    """Complete a shadow manual task.

    If verified is False, sets status='completed_self_reported' and records 'practiced_self_reported'.
    If verified is True, sets status='completed_verified' and records 'practiced_verified'.
    """
    db = _get_db()
    now = _utcnow_iso()
    task_status = "completed_verified" if verified else "completed_self_reported"
    skill_status = "practiced_verified" if verified else "practiced_self_reported"

    db.execute(
        "UPDATE shadow_manual_tasks SET status = ?, notes = ?, updated_at = ? "
        "WHERE report_token = ? AND vuln_type = ?",
        (task_status, notes, now, report_token, vuln_type),
    )
    db.commit()

    # Update skill ledger
    record_skill_progress(
        user_id=user_id,
        vuln_type=vuln_type,
        status=skill_status,
        evidence_ref=f"shadow_report:{report_token}",
    )

    return {
        "report_token": report_token,
        "vuln_type": vuln_type,
        "status": task_status,
        "notes": notes,
        "updated_at": now,
    }
