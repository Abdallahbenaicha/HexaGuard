"""Permanent Regression Test Suite for P0 Remediations.

Validates:
1. P0-1 (DEV-01 Transaction Atomicity):
   - Atomic commit on normal completion (attempt completed + evidence recorded).
   - Atomic rollback on simulated crash (zero orphaned evidence rows, attempt unchanged).
2. P0-2 (Evidence Uniqueness & Idempotent Merge):
   - Replay/Duplicate injection for the same attempt/source merges into 1 record.
   - Merging preserves MAX(score) and MAX(is_verified).
   - Distinct attempts (legitimate user retries) have distinct evidence_sources and are NOT blocked.
3. P0-3 (Multi-Worker Startup Guard):
   - Normal startup (workers=1 or unset) succeeds.
   - Startup with WEB_CONCURRENCY > 1, GUNICORN_WORKERS > 1, or WORKERS > 1 raises RuntimeError.
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import patch

from app import create_app
from database import (
    init_db,
    create_user,
    get_user_by_username,
    create_exercise,
    get_exercises_for_skill,
    start_exercise_attempt,
    get_attempt,
    complete_exercise_attempt,
    get_capability_evidence,
)
from db.skills import record_capability_evidence
from seed_learning import seed


@pytest.fixture(autouse=True)
def setup_p0_test_env(tmp_path, monkeypatch):
    """Set up isolated test database for P0 regression testing."""
    test_db = str(tmp_path / "test_p0_regression.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-p0-secret")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)

    init_db()
    seed()


# ── P0-1: DEV-01 Transaction Atomicity ─────────────────────────────────────────

def test_dev01_atomic_transaction_success_and_rollback():
    """Verify that complete_exercise_attempt is strictly atomic under success and rollback."""
    create_user("p0_student", "Password123!", role="analyst", email="p0@example.com")
    user = get_user_by_username("p0_student")
    user_id = user["id"]

    ex_list = get_exercises_for_skill("http_fundamentals", capability="knowledge")
    assert len(ex_list) > 0
    ex = ex_list[0]

    # --- Case 1: Normal Completion commits attempt and evidence atomically ---
    attempt_normal = start_exercise_attempt(user_id, ex["id"])
    att_id_1 = attempt_normal["id"]

    valid_text = (
        "HTTP methods include GET, POST, PUT, DELETE. "
        "Status codes are 200 OK, 301 Redirect, 400 Bad Request, 401 Unauthorized, "
        "403 Forbidden, 404 Not Found, 500 Internal Server Error. "
        "Headers provide metadata and cookies for session management."
    )

    res_normal = complete_exercise_attempt(att_id_1, user_id, valid_text)
    assert res_normal["result"] == "passed"
    assert res_normal["attempt"]["evaluation_status"] in ("auto_evaluated", "completed")

    # Verify both attempt and evidence exist in DB
    att_row = get_attempt(att_id_1)
    assert att_row["evaluation_status"] in ("auto_evaluated", "completed")
    assert att_row["completed_at"] is not None

    ev_normal = get_capability_evidence(user_id, "http_fundamentals", "knowledge")
    assert len(ev_normal) == 1
    assert ev_normal[0]["evidence_source"] == f"exercise_attempt:{att_id_1}"

    # --- Case 2: Crash/Exception during finalization causes complete rollback ---
    attempt_crash = start_exercise_attempt(user_id, ex["id"])
    att_id_2 = attempt_crash["id"]

    from db.learning import _get_db
    import sqlite3
    real_conn = _get_db()

    class DBProxy:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args, **kwargs):
            if isinstance(sql, str) and "UPDATE exercise_attempts" in sql:
                raise sqlite3.OperationalError("Simulated failure during attempt update!")
            return self._conn.execute(sql, *args, **kwargs)

        def rollback(self):
            return self._conn.rollback()

        def commit(self):
            return self._conn.commit()

        def __getattr__(self, name):
            return getattr(self._conn, name)

    proxy = DBProxy(real_conn)
    with patch("db.learning._get_db", return_value=proxy):
        with pytest.raises(sqlite3.OperationalError, match="Simulated failure during attempt update!"):
            complete_exercise_attempt(att_id_2, user_id, valid_text)

    # Verification: att_id_2 must remain in_progress/pending, and NO orphaned evidence for att_id_2 exists
    att_crashed_row = get_attempt(att_id_2)
    assert att_crashed_row["evaluation_status"] == "pending"
    assert att_crashed_row["completed_at"] is None

    all_evidence = get_capability_evidence(user_id, "http_fundamentals", "knowledge")
    # Only the first normal attempt's evidence should be present; second must be rolled back!
    assert len(all_evidence) == 1
    assert all_evidence[0]["evidence_source"] == f"exercise_attempt:{att_id_1}"


# ── P0-2: Evidence Uniqueness & Idempotent Merging ─────────────────────────────

def test_evidence_uniqueness_and_idempotent_merge():
    """Verify that duplicate evidence injections for the same source are merged idempotently."""
    create_user("p0_student2", "Password123!", role="analyst", email="p0_2@example.com")
    user = get_user_by_username("p0_student2")
    user_id = user["id"]

    source_tag = "exercise_attempt:888001"

    # 1. First insertion: score=0.6, is_verified=0
    ev1 = record_capability_evidence(
        user_id=user_id,
        vuln_type="sqli",
        capability="recognition",
        evidence_type="EVALUATED",
        evidence_source=source_tag,
        source_id="888001",
        is_verified=0,
        score=0.6,
        notes="First attempt",
    )
    assert ev1["id"] is not None

    # 2. Duplicate insertion with higher score: score=0.85, is_verified=0
    ev2 = record_capability_evidence(
        user_id=user_id,
        vuln_type="sqli",
        capability="recognition",
        evidence_type="EVALUATED",
        evidence_source=source_tag,
        source_id="888001",
        is_verified=0,
        score=0.85,
        notes="Second attempt higher score",
    )

    # 3. Duplicate insertion with lower score but is_verified=1: score=0.7, is_verified=1
    ev3 = record_capability_evidence(
        user_id=user_id,
        vuln_type="sqli",
        capability="recognition",
        evidence_type="VERIFIED",
        evidence_source=source_tag,
        source_id="888001",
        is_verified=1,
        score=0.7,
        notes="Third attempt verified",
    )

    # Assert exactly 1 row exists in DB for this source
    evidence_rows = get_capability_evidence(user_id, "sqli", "recognition")
    assert len(evidence_rows) == 1

    canonical = evidence_rows[0]
    assert canonical["evidence_source"] == source_tag
    # Merged row must retain MAX(score) -> 0.85 and MAX(is_verified) -> 1
    assert canonical["score"] == pytest.approx(0.85)
    assert canonical["is_verified"] == 1


def test_evidence_distinct_attempts_allow_retries():
    """Verify that distinct attempts (legitimate user retries) create distinct evidence rows."""
    create_user("p0_student3", "Password123!", role="analyst", email="p0_3@example.com")
    user = get_user_by_username("p0_student3")
    user_id = user["id"]

    # Legitimate Attempt 1
    ev_att1 = record_capability_evidence(
        user_id=user_id,
        vuln_type="xss",
        capability="knowledge",
        evidence_type="EVALUATED",
        evidence_source="exercise_attempt:1001",
        source_id="1001",
        is_verified=0,
        score=0.5,
        notes="Attempt 1",
    )

    # Legitimate Attempt 2 (User retried to improve score)
    ev_att2 = record_capability_evidence(
        user_id=user_id,
        vuln_type="xss",
        capability="knowledge",
        evidence_type="EVALUATED",
        evidence_source="exercise_attempt:1002",
        source_id="1002",
        is_verified=0,
        score=0.9,
        notes="Attempt 2 - Improved",
    )

    # Both attempts must be preserved because evidence_source differs
    evidence_rows = get_capability_evidence(user_id, "xss", "knowledge")
    assert len(evidence_rows) == 2
    sources = [r["evidence_source"] for r in evidence_rows]
    assert "exercise_attempt:1001" in sources
    assert "exercise_attempt:1002" in sources


# ── P0-3: Multi-Worker Startup Guard ──────────────────────────────────────────

def test_multi_worker_startup_guard(monkeypatch):
    """Verify that create_app strictly rejects startup if workers > 1."""
    # Workers = 1 succeeds
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    app1 = create_app()
    assert app1 is not None

    # WEB_CONCURRENCY = 2 raises RuntimeError
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    with pytest.raises(RuntimeError, match="CRITICAL ARCHITECTURAL CONCURRENCY RISK.*WEB_CONCURRENCY=2"):
        create_app()

    # GUNICORN_WORKERS = 4 raises RuntimeError
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("GUNICORN_WORKERS", "4")
    with pytest.raises(RuntimeError, match="CRITICAL ARCHITECTURAL CONCURRENCY RISK.*GUNICORN_WORKERS=4"):
        create_app()

    # WORKERS = 3 raises RuntimeError
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    monkeypatch.setenv("WORKERS", "3")
    with pytest.raises(RuntimeError, match="CRITICAL ARCHITECTURAL CONCURRENCY RISK.*WORKERS=3"):
        create_app()
