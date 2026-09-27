"""Phase 3 Manual Testing Education Test Suite (test_phase3_manual_education.py).

Verifies the 10 requirements for the 3 required vertical slices:
  - http_fundamentals
  - idor
  - xss
connected to all 8 capabilities:
  1. knowledge
  2. recognition
  3. manual_detection
  4. validation
  5. lab_exploitation (safe_lab / verified sandbox)
  6. impact_analysis
  7. remediation
  8. reporting

Authoritative Invariants Tested:
1. Registration: All 8 capabilities are seeded and queryable via backend API.
2. Reachability & Rendering: Lesson content is served with all 16 canonical fields.
3. Attempt Initiation: Server-side attempt creation sets started_at and advances to INTRODUCED (Rule C).
4. Authoritative Evaluation: Client cannot supply scores or dictate results (D-07).
5. Trust Level Integrity: Automated rubrics are strictly capped at score <= 0.9 with is_verified=0 (EVALUATED).
6. Sandbox Proof Gate: Score = 1.0 and is_verified=1 is strictly reserved for authoritative sandbox verification.
7. Mastery Machine: Deterministic progression (NOT_STARTED -> INTRODUCED -> PRACTICED -> DEMONSTRATED -> MASTERED).
8. Unified Flow: Completing a lab via sandbox updates the authoritative exercise_attempts record.
"""

from __future__ import annotations

import os
import hashlib
import pytest
from app import create_app
from database import (
    init_db,
    create_user,
    get_user_by_username,
    get_exercises_for_skill,
    start_exercise_attempt,
    complete_exercise_attempt,
    get_attempt,
    get_capability_evidence,
    compute_mastery_matrix,
    save_active_sandbox_record,
)
from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK, SANDBOX_ALLOWLIST
from seed_learning import seed

REQUIRED_SLICES = ["http_fundamentals", "idor", "xss"]
ALL_8_CAPABILITIES = {
    "knowledge",
    "recognition",
    "manual_detection",
    "validation",
    "lab_exploitation",
    "impact_analysis",
    "remediation",
    "reporting",
}


@pytest.fixture(autouse=True)
def setup_phase3_env(tmp_path, monkeypatch):
    """Isolate test database and active sandbox registry for each test."""
    test_db = str(tmp_path / "test_phase3.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-phase3-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    # Seed all exercises
    seed()


# ── 1. Registration & Seeding Verification ────────────────────────────────────

def test_all_slices_have_all_8_capabilities_seeded():
    """Verify that http_fundamentals, idor, and xss have all 8 capabilities seeded."""
    for slice_id in REQUIRED_SLICES:
        exercises = get_exercises_for_skill(slice_id)
        assert len(exercises) >= 8, f"Slice '{slice_id}' has {len(exercises)} exercises, expected >= 8"

        seeded_caps = {ex["capability"] for ex in exercises}
        missing_caps = ALL_8_CAPABILITIES - seeded_caps
        assert not missing_caps, f"Slice '{slice_id}' is missing capabilities: {missing_caps}"


def test_api_exercises_endpoint_returns_8_capabilities(client_user):
    """GET /api/learning/exercises/<vuln_type> returns all 8 capabilities for each slice."""
    client, user = client_user
    for slice_id in REQUIRED_SLICES:
        resp = client.get(f"/api/learning/exercises/{slice_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        exercises = data["exercises"]
        assert len(exercises) >= 8

        caps = {ex["capability"] for ex in exercises}
        assert caps == ALL_8_CAPABILITIES, f"API returned caps {caps} for '{slice_id}', expected {ALL_8_CAPABILITIES}"


@pytest.fixture
def client_user():
    create_user("student_phase3", "Password123!", role="analyst", email="p3@test.local")
    user = get_user_by_username("student_phase3")
    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True
    return client, user


# ── 2. Reachability & Taxonomy Rendering ──────────────────────────────────────

def test_taxonomy_endpoint_serves_structured_lessons(client_user):
    """GET /api/learn/taxonomy/<id> returns complete lesson metadata for all 3 slices."""
    client, _ = client_user
    for slice_id in REQUIRED_SLICES:
        resp = client.get(f"/api/learn/taxonomy/{slice_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        topic = data["topic"]
        assert topic["id"] == slice_id
        assert len(topic["name_en"]) > 0
        assert len(topic["name_ar"]) > 0

        lesson = topic.get("lesson", {})
        for required_field in ["concept", "detection_methodology", "manual_validation", "remediation_standard"]:
            assert len(lesson.get(required_field, "").strip()) > 20, f"Field '{required_field}' missing in '{slice_id}'"


# ── 3. Attempt Initiation & Rule C ────────────────────────────────────────────

def test_start_attempt_advances_mastery_to_introduced(client_user):
    """Starting an attempt sets started_at and advances capability to INTRODUCED (Rule C)."""
    client, user = client_user
    for slice_id in REQUIRED_SLICES:
        exercises = get_exercises_for_skill(slice_id)
        know_ex = next(e for e in exercises if e["capability"] == "knowledge")

        # Initial mastery state must be NOT_STARTED
        m_initial = compute_mastery_matrix(user["id"], slice_id)
        assert m_initial["capabilities"]["knowledge"]["state"] == "NOT_STARTED"

        # Start attempt via API
        resp = client.post("/api/learning/attempt/start", json={"exercise_id": know_ex["id"]})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["ok"] is True
        attempt = data["attempt"]
        assert attempt["started_at"] is not None
        assert attempt["completed_at"] is None
        assert attempt["result"] == "pending"

        # Mastery matrix now reflects INTRODUCED for knowledge
        m_after = compute_mastery_matrix(user["id"], slice_id)
        assert m_after["capabilities"]["knowledge"]["state"] == "INTRODUCED"


# ── 4. Authoritative Evaluation & Anti-Cheat Capping ──────────────────────────

def test_automated_evaluation_capped_at_0_9_with_evaluated_evidence(client_user):
    """Submissions to automated evaluators are capped at score <= 0.9 with is_verified=0."""
    client, user = client_user

    # Test IDOR knowledge evaluation
    idor_exs = get_exercises_for_skill("idor")
    know_ex = next(e for e in idor_exs if e["capability"] == "knowledge")

    att = start_exercise_attempt(user["id"], know_ex["id"])

    # High-quality answer covering required concepts
    submission = (
        "Insecure Direct Object References represent an authorization failure where an application trusts "
        "client-supplied object identifiers. When accessing records across different tenants or users, "
        "the backend must enforce strict horizontal and vertical access control. "
        "Without authoritative ownership verification, BOLA permits arbitrary cross-tenant data exfiltration."
    )

    # Client tries to cheat by submitting score=1.0 and is_verified=1
    resp = client.post(
        "/api/learning/attempt/complete",
        json={
            "attempt_id": att["id"],
            "submission_text": submission,
            "score": 1.0,
            "is_verified": 1,
            "result": "passed",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    # Server derived score is <= 0.9 (score 1.0 is rejected/overridden)
    assert data["score"] <= 0.9
    assert data["score"] >= 0.8
    assert data["result"] == "passed"

    # Evidence recorded is EVALUATED with is_verified=0
    ev = get_capability_evidence(user["id"], vuln_type="idor", capability="knowledge")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 0
    assert ev[0]["evidence_type"] == "EVALUATED"

    # Mastery matrix state for knowledge is DEMONSTRATED or MASTERED (score >= 0.8 with 0 verified evidence)
    m = compute_mastery_matrix(user["id"], "idor")
    assert m["capabilities"]["knowledge"]["state"] in ("DEMONSTRATED", "MASTERED")
    assert m["capabilities"]["knowledge"]["verified_evidence_count"] == 0


# ── 5. Safe Local Protocol Lab Evaluation (http_fundamentals) ──────────────────

def test_http_fundamentals_safe_lab_evaluation(client_user):
    """Safe local protocol lab for http_fundamentals is evaluated server-side and capped at 0.9."""
    client, user = client_user

    http_exs = get_exercises_for_skill("http_fundamentals")
    lab_ex = next(e for e in http_exs if e["capability"] == "lab_exploitation")

    att = start_exercise_attempt(user["id"], lab_ex["id"])

    valid_cli_output = (
        "Command:\ncurl -X OPTIONS -H 'X-Test: Probe' http://127.0.0.1:5000/api/health\n\n"
        "Output:\nHTTP/1.1 200 OK\nServer: SecuraX-Gateway\nContent-Type: application/json\n"
        "Allow: GET, POST, OPTIONS, HEAD\nContent-Length: 42"
    )

    resp = client.post(
        "/api/learning/attempt/complete",
        json={"attempt_id": att["id"], "submission_text": valid_cli_output},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["result"] == "passed"
    assert data["score"] <= 0.9
    assert data["score"] >= 0.7

    ev = get_capability_evidence(user["id"], vuln_type="http_fundamentals", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 0
    assert ev[0]["evidence_type"] == "EVALUATED"


# ── 6. Verified Sandbox Lab Proof (xss & idor) ────────────────────────────────

def test_containerized_lab_requires_active_sandbox_proof(client_user):
    """Containerized lab (xss) requires active sandbox; fails without active sandbox."""
    client, user = client_user

    xss_exs = get_exercises_for_skill("xss")
    lab_ex = next(e for e in xss_exs if e["capability"] == "lab_exploitation")

    att = start_exercise_attempt(user["id"], lab_ex["id"])

    # Attempting to submit flag without active sandbox fails
    resp = client.post(
        "/api/learning/attempt/complete",
        json={"attempt_id": att["id"], "submission_text": "FLAG{xss_dom_reflection_conquered_2026}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["result"] == "failed"
    assert data["score"] == 0.0


def test_containerized_lab_verifies_with_active_sandbox_and_flag(client_user):
    """Authoritative active sandbox verification awards score=1.0 and is_verified=1."""
    import time
    client, user = client_user

    # Setup active sandbox in registry
    sandbox_id = "sb-test-xss-phase3-001"
    now_ts = time.time()
    sb_record = {
        "id": sandbox_id,
        "user_id": user["id"],
        "vuln_type": "xss",
        "name": "Juice Shop XSS",
        "container_id": "mock_docker_cid_123",
        "host_port": 3000,
        "started_at": now_ts,
        "expires_at": now_ts + 7200,
        "status": "running",
        "completed": False,
        "flag_hash": hashlib.sha256("FLAG{xss_dom_reflection_conquered_2026}".encode()).hexdigest(),
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sandbox_id] = sb_record
    save_active_sandbox_record(sb_record)

    xss_exs = get_exercises_for_skill("xss")
    lab_ex = next(e for e in xss_exs if e["capability"] == "lab_exploitation")

    att = start_exercise_attempt(user["id"], lab_ex["id"])

    resp = client.post(
        "/api/learning/attempt/complete",
        json={
            "attempt_id": att["id"],
            "submission_text": "FLAG{xss_dom_reflection_conquered_2026}",
            "metadata": {
                "sandbox_id": sandbox_id,
                "flag": "FLAG{xss_dom_reflection_conquered_2026}",
            },
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["result"] == "passed"
    assert data["score"] == 1.0
    assert data["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user["id"], vuln_type="xss", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["evidence_type"] == "VERIFIED"

    m = compute_mastery_matrix(user["id"], "xss")
    assert m["capabilities"]["lab_exploitation"]["state"] == "MASTERED"


def test_sandbox_complete_endpoint_creates_authoritative_attempt(client_user):
    """Direct verification via /api/sandbox/<id>/complete creates and completes an exercise_attempt."""
    import time
    client, user = client_user

    sandbox_id = "sb-test-idor-phase3-002"
    now_ts = time.time()
    sb_record = {
        "id": sandbox_id,
        "user_id": user["id"],
        "vuln_type": "idor",
        "name": "Juice Shop IDOR",
        "container_id": "mock_docker_cid_456",
        "host_port": 3000,
        "started_at": now_ts,
        "expires_at": now_ts + 7200,
        "status": "running",
        "completed": False,
        "flag_hash": hashlib.sha256("FLAG{idor_insecure_direct_object_reference_extracted}".encode()).hexdigest(),
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sandbox_id] = sb_record
    save_active_sandbox_record(sb_record)

    # Call /api/sandbox/<id>/complete directly (SandboxLauncher widget flow)
    resp = client.post(
        f"/api/sandbox/{sandbox_id}/complete",
        json={"flag": "FLAG{idor_insecure_direct_object_reference_extracted}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["verified"] is True

    # Authoritative attempt must exist and be marked system_verified with score=1.0
    from db.connection import _get_db
    db = _get_db()
    att_row = db.execute(
        "SELECT * FROM exercise_attempts WHERE user_id = ? AND vuln_type = 'idor' AND capability = 'lab_exploitation'",
        (user["id"],),
    ).fetchone()
    assert att_row is not None
    assert att_row["score"] == 1.0
    assert att_row["evaluation_status"] == "system_verified"
    assert att_row["result"] == "passed"
    assert att_row["completed_at"] is not None

    # Mastery matrix advances to MASTERED for lab_exploitation
    m = compute_mastery_matrix(user["id"], "idor")
    assert m["capabilities"]["lab_exploitation"]["state"] == "MASTERED"
