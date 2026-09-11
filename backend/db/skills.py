"""SecuraX Database Module — Skill Ledger & Shadow Manual Tasks (v1).

Manages user skill progression (Skill Ledger) and post-scan manual hunting
lessons (Shadow Manual Tasks).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
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


SKILL_CAPABILITIES = [
    "knowledge",        # Conceptual understanding of the vulnerability
    "recognition",      # Identifying the pattern in code / scanner output
    "manual_detection", # Finding it manually in a real or exercise target
    "validation",       # Proving it is a true positive, not a false positive
    "lab_exploitation", # Safely exploiting in a sandboxed environment
    "impact_analysis",  # Articulating realistic business/technical impact
    "remediation",      # Applying and verifying the correct fix
    "reporting",        # Producing a professional-quality bug report
]

CAPABILITY_PREREQUISITES: dict[str, list[str]] = {}  # Empty in Phase 1 per Task 7.4 M-4


def _parse_iso(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    s = str(ts)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def complete_shadow_task(
    report_token: str,
    vuln_type: str,
    user_id: int,
    notes: str = "",
) -> dict[str, Any] | None:
    """Complete a shadow manual task (self-reported only).

    SEC-01: Removes client-controlled 'verified' flag. Always sets
            status='completed_self_reported' and records 'practiced_self_reported'.
    SEC-05: Enforces dual-layer ownership (scan report ownership AND task ownership).
    """
    db = _get_db()

    # Layer 1: Report ownership check
    report = db.execute(
        "SELECT id, token, user_id FROM scan_reports WHERE token = ?",
        (report_token,),
    ).fetchone()
    if not report or report["user_id"] != user_id:
        return None

    # Layer 2: Task existence and ownership check
    task = db.execute(
        "SELECT id, report_token, user_id, vuln_type, status FROM shadow_manual_tasks "
        "WHERE report_token = ? AND vuln_type = ?",
        (report_token, vuln_type),
    ).fetchone()
    if not task:
        return None
    if task["user_id"] != user_id:
        return None

    now = _utcnow_iso()
    task_status = "completed_self_reported"
    skill_status = "practiced_self_reported"

    db.execute(
        "UPDATE shadow_manual_tasks SET status = ?, notes = ?, updated_at = ? "
        "WHERE report_token = ? AND vuln_type = ? AND user_id = ?",
        (task_status, notes, now, report_token, vuln_type, user_id),
    )
    db.commit()

    # Update legacy skill ledger
    record_skill_progress(
        user_id=user_id,
        vuln_type=vuln_type,
        status=skill_status,
        evidence_ref=f"shadow_report:{report_token}",
    )

    # Task 7.3 & 10.1: Shadow task creates SELF_REPORTED evidence for manual_detection (is_verified=0)
    record_capability_evidence(
        user_id=user_id,
        vuln_type=vuln_type,
        capability="manual_detection",
        evidence_type="SELF_REPORTED",
        evidence_source=f"shadow_report:{report_token}",
        is_verified=0,
        notes=notes,
    )

    return {
        "report_token": report_token,
        "vuln_type": vuln_type,
        "status": task_status,
        "notes": notes,
        "updated_at": now,
    }


def record_capability_evidence(
    user_id: int,
    vuln_type: str,
    capability: str,
    evidence_type: str,
    evidence_source: str,
    source_id: Optional[str] = None,
    is_verified: int = 0,
    score: Optional[float] = None,
    notes: Optional[str] = None,
) -> dict[str, Any]:
    """Record capability evidence for a user and vulnerability type.

    Rule E: is_verified can only be 1 if from trusted server-side events.
    Rule B: SELF_REPORTED evidence has is_verified=0.
    """
    db = _get_db()
    now = _utcnow_iso()
    v_flag = 1 if is_verified else 0
    cur = db.execute(
        "INSERT INTO skill_capability_evidence "
        "(user_id, vuln_type, capability, evidence_type, evidence_source, source_id, is_verified, score, notes, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, vuln_type, capability, evidence_type, evidence_source, source_id, v_flag, score, notes, now),
    )
    db.commit()
    ev_id = getattr(cur, "lastrowid", None)
    return {
        "id": ev_id,
        "user_id": user_id,
        "vuln_type": vuln_type,
        "capability": capability,
        "evidence_type": evidence_type,
        "evidence_source": evidence_source,
        "source_id": source_id,
        "is_verified": v_flag,
        "score": score,
        "notes": notes,
        "created_at": now,
    }


def get_capability_evidence(
    user_id: int,
    vuln_type: Optional[str] = None,
    capability: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Retrieve capability evidence records for a user with optional filters."""
    db = _get_db()
    sql = (
        "SELECT id, user_id, vuln_type, capability, evidence_type, evidence_source, "
        "source_id, is_verified, score, notes, created_at "
        "FROM skill_capability_evidence WHERE user_id = ?"
    )
    params: list[Any] = [user_id]
    if vuln_type:
        sql += " AND vuln_type = ?"
        params.append(vuln_type)
    if capability:
        sql += " AND capability = ?"
        params.append(capability)
    sql += " ORDER BY created_at DESC"
    rows = db.execute(sql, tuple(params)).fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "vuln_type": r["vuln_type"],
            "capability": r["capability"],
            "evidence_type": r["evidence_type"],
            "evidence_source": r["evidence_source"],
            "source_id": r["source_id"],
            "is_verified": int(r["is_verified"]),
            "score": float(r["score"]) if r["score"] is not None else None,
            "notes": r["notes"],
            "created_at": r["created_at"],
        })
    return results


def skill_mastery_level(cap_states: dict[str, str]) -> str:
    """Derives skill-level mastery state from the 8 capability states.

    Phase 1 design: quantity-based rollup (D-04).
    """
    counts = {
        "NOT_STARTED": 0,
        "INTRODUCED": 0,
        "PRACTICED": 0,
        "DEMONSTRATED": 0,
        "MASTERED": 0,
    }
    for s in cap_states.values():
        if s in counts:
            counts[s] += 1

    mastered   = counts["MASTERED"]
    demo_plus  = counts["DEMONSTRATED"] + mastered
    prac_plus  = counts["PRACTICED"]    + demo_plus
    intro_plus = counts["INTRODUCED"]  + prac_plus

    if mastered   == 8: return "MASTERED"
    if demo_plus  >= 6: return "DEMONSTRATED"
    if prac_plus  >= 4: return "PRACTICED"
    if intro_plus >= 1: return "INTRODUCED"
    return "NOT_STARTED"


def compute_mastery_matrix(user_id: int, vuln_type: str) -> dict[str, Any]:
    """Computes the five-state mastery machine for all 8 capabilities deterministically.

    Follows Task 7.4 (v3) specifications:
    - NOT_STARTED: zero exercise_attempts records.
    - INTRODUCED: >=1 exercise_attempts record (Rule C: engagement-only, zero evidence weight).
    - PRACTICED: evaluated attempt with score >= 0.5.
    - DEMONSTRATED: verified evidence (Option A) OR evaluated attempt with score >= 0.8 (Option B).
    - MASTERED: M-1 (DEMONSTRATED), M-2 (recency <= 90 days), M-3 (no unsuperseded failure < 0.3 in 30 days), M-4 (prerequisites).
    """
    db = _get_db()
    now_dt = datetime.now(timezone.utc)
    ninety_days_ago = now_dt - timedelta(days=90)
    thirty_days_ago = now_dt - timedelta(days=30)

    # Load attempts for this user and vuln_type
    attempts_rows = db.execute(
        "SELECT id, exercise_id, vuln_type, capability, attempt_number, started_at, "
        "completed_at, score, hints_used, aria_calls_used, solution_viewed, "
        "result, evaluation_status "
        "FROM exercise_attempts "
        "WHERE user_id = ? AND vuln_type = ? "
        "ORDER BY id ASC",
        (user_id, vuln_type),
    ).fetchall()
    attempts = [dict(r) for r in attempts_rows]

    # Load evidence for this user and vuln_type
    evidence_rows = db.execute(
        "SELECT id, user_id, vuln_type, capability, evidence_type, evidence_source, "
        "source_id, is_verified, score, notes, created_at "
        "FROM skill_capability_evidence "
        "WHERE user_id = ? AND vuln_type = ? "
        "ORDER BY created_at ASC",
        (user_id, vuln_type),
    ).fetchall()
    evidence = [dict(r) for r in evidence_rows]

    cap_details: dict[str, dict[str, Any]] = {}
    cap_states: dict[str, str] = {}

    for cap in SKILL_CAPABILITIES:
        cap_att = [a for a in attempts if a["capability"] == cap]
        cap_ev = [e for e in evidence if e["capability"] == cap]

        # 1. Check NOT_STARTED
        if not cap_att:
            has_verified_ev = any(int(e.get("is_verified", 0)) == 1 for e in cap_ev)
            if not has_verified_ev:
                cap_states[cap] = "NOT_STARTED"
                cap_details[cap] = {
                    "state": "NOT_STARTED",
                    "attempts_count": 0,
                    "evidence_count": len(cap_ev),
                    "verified_evidence_count": 0,
                    "latest_score": None,
                    "latest_activity_at": None,
                }
                continue

        # 2. Base state if attempts exist: INTRODUCED (Rule C: engagement state only)
        state = "INTRODUCED" if cap_att else "NOT_STARTED"

        # 3. Check PRACTICED: score >= 0.5 on evaluated completed attempt
        practiced_attempts = [
            a for a in cap_att
            if a.get("completed_at")
            and a.get("evaluation_status") in ("auto_evaluated", "human_evaluated")
            and a.get("score") is not None
            and float(a["score"]) >= 0.5
        ]
        if practiced_attempts:
            state = "PRACTICED"

        # 4. Check DEMONSTRATED: Option A (verified evidence) OR Option B (score >= 0.8)
        verified_evidence = [e for e in cap_ev if int(e.get("is_verified", 0)) == 1]
        high_score_attempts = [
            a for a in cap_att
            if a.get("completed_at")
            and a.get("evaluation_status") in ("auto_evaluated", "human_evaluated", "system_verified")
            and a.get("score") is not None
            and float(a["score"]) >= 0.8
        ]
        if verified_evidence or high_score_attempts:
            state = "DEMONSTRATED"

        # 5. Check MASTERED
        if state == "DEMONSTRATED":
            # M-1: is DEMONSTRATED (True)

            # M-2: Recency <= 90 days of latest qualifying event
            qualifying_dates: list[datetime] = []
            for e in verified_evidence:
                if e.get("created_at"):
                    qualifying_dates.append(_parse_iso(e["created_at"]))
            for a in high_score_attempts:
                if a.get("completed_at"):
                    qualifying_dates.append(_parse_iso(a["completed_at"]))

            if qualifying_dates:
                latest_qualifying_success_dt = max(qualifying_dates)
                m2_passes = (latest_qualifying_success_dt >= ninety_days_ago)
            else:
                m2_passes = False
                latest_qualifying_success_dt = None

            # M-3: No unsuperseded recent failure within 30 days
            blocking_failures = [
                a for a in cap_att
                if a.get("completed_at")
                and a.get("evaluation_status") in ("auto_evaluated", "human_evaluated")
                and a.get("score") is not None
                and float(a["score"]) < 0.3
                and _parse_iso(a["completed_at"]) >= thirty_days_ago
            ]
            if not blocking_failures:
                m3_passes = True
            else:
                latest_blocking_failure_dt = max(_parse_iso(a["completed_at"]) for a in blocking_failures)
                if latest_qualifying_success_dt and latest_qualifying_success_dt > latest_blocking_failure_dt:
                    m3_passes = True
                else:
                    m3_passes = False

            # M-4: Prerequisites (trivially True in Phase 1)
            prereqs = CAPABILITY_PREREQUISITES.get(cap, [])
            m4_passes = all(cap_states.get(p) in ("DEMONSTRATED", "MASTERED") for p in prereqs)

            if m2_passes and m3_passes and m4_passes:
                state = "MASTERED"

        cap_states[cap] = state

        # Latest score and activity timestamp
        latest_score = None
        for a in reversed(cap_att):
            if a.get("score") is not None:
                latest_score = float(a["score"])
                break

        latest_ts = None
        if cap_att and cap_att[-1].get("completed_at"):
            latest_ts = cap_att[-1]["completed_at"]
        elif cap_att and cap_att[-1].get("started_at"):
            latest_ts = cap_att[-1]["started_at"]
        elif cap_ev:
            latest_ts = cap_ev[-1]["created_at"]

        cap_details[cap] = {
            "state": state,
            "attempts_count": len(cap_att),
            "evidence_count": len(cap_ev),
            "verified_evidence_count": len(verified_evidence),
            "latest_score": latest_score,
            "latest_activity_at": latest_ts,
        }

    skill_level = skill_mastery_level(cap_states)
    summary_counts = {
        "NOT_STARTED": sum(1 for s in cap_states.values() if s == "NOT_STARTED"),
        "INTRODUCED": sum(1 for s in cap_states.values() if s == "INTRODUCED"),
        "PRACTICED": sum(1 for s in cap_states.values() if s == "PRACTICED"),
        "DEMONSTRATED": sum(1 for s in cap_states.values() if s == "DEMONSTRATED"),
        "MASTERED": sum(1 for s in cap_states.values() if s == "MASTERED"),
    }

    return {
        "vuln_type": vuln_type,
        "user_id": user_id,
        "capabilities": cap_details,
        "capability_states": cap_states,
        "skill_level": skill_level,
        "summary": summary_counts,
    }

