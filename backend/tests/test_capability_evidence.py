"""Capability Evidence and Five-State Mastery Engine Tests (test_capability_evidence.py).

Verifies:
- Rule A: Engagement events (lesson view, hint copy, ARIA solution) create no evidence.
- Rule B: Self-report events produce zero capability mastery movement.
- Rule C: INTRODUCED is an engagement state only (from attempt start), carries zero evidence weight.
- Rule D: EVALUATED evidence is computed by backend evaluator, advances to PRACTICED (>=0.5) or DEMONSTRATED (>=0.8).
- Rule E: VERIFIED evidence is server-side only (sandbox flag verified).
- User isolation: User cannot read another user's evidence.
"""

from datetime import datetime, timezone
import pytest
from database import (
    init_db,
    create_user,
    get_user_by_username,
    store_report,
    create_exercise,
    start_exercise_attempt,
    complete_exercise_attempt,
    record_capability_evidence,
    get_capability_evidence,
    compute_mastery_matrix,
    complete_shadow_task,
    _get_db,
)
from app import create_app


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_capability_evidence.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-cap-evidence-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_sandbox_flag_creates_lab_exploitation_verified_evidence():
    """Server-side sandbox flag verification creates is_verified=1 evidence for lab_exploitation."""
    create_user("sandbox_learner", "Password123!", role="analyst", email="sb_learner@test.local")
    user = get_user_by_username("sandbox_learner")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Launch & complete with valid flag
    launch_resp = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    sb_id = launch_resp.get_json()["sandbox"]["id"]
    comp_resp = client.post(
        f"/api/sandbox/{sb_id}/complete",
        json={"flag": "FLAG{xss_dom_reflection_conquered_2026}"},
    )
    assert comp_resp.status_code == 200

    evidence = get_capability_evidence(user["id"], vuln_type="xss", capability="lab_exploitation")
    assert len(evidence) >= 1
    assert evidence[0]["is_verified"] == 1
    assert evidence[0]["evidence_type"] == "VERIFIED"


def test_lesson_view_creates_no_evidence():
    """Rule A: Viewing a lesson or clicking complete creates NO evidence or attempt rows."""
    create_user("reader_user", "Password123!", role="analyst", email="reader@test.local")
    user = get_user_by_username("reader_user")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Call lesson detail
    resp = client.get("/api/learn/lesson/xss")
    assert resp.status_code in (200, 404)

    evidence = get_capability_evidence(user["id"], vuln_type="xss")
    assert len(evidence) == 0

    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["skill_level"] == "NOT_STARTED"


def test_self_report_api_creates_no_capability_evidence():
    """Rule B: Legacy self-report API does not advance capability mastery."""
    create_user("reporter_user", "Password123!", role="analyst", email="reporter@test.local")
    user = get_user_by_username("reporter_user")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post(
        "/api/skill/self-report",
        json={"vuln_type": "sqli", "notes": "Self-reported practice"},
    )
    assert resp.status_code == 200

    matrix = compute_mastery_matrix(user["id"], "sqli")
    assert matrix["capabilities"]["knowledge"]["state"] == "NOT_STARTED"
    assert matrix["skill_level"] == "NOT_STARTED"


def test_aria_solution_creates_no_evidence():
    """Rule A: Requesting ARIA solution (override phrase) creates no capability evidence."""
    create_user("aria_learner", "Password123!", role="analyst", email="aria_l@test.local")
    user = get_user_by_username("aria_learner")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post(
        "/api/ai/chat",
        json={"message": "reveal solution", "context": {"target": "http://test.local"}},
    )
    assert resp.status_code == 200

    evidence = get_capability_evidence(user["id"])
    assert len(evidence) == 0


def test_dojo_mcq_creates_no_capability_evidence():
    """Rule A/B: Completing daily Dojo MCQ updates legacy record but creates no verified capability evidence."""
    create_user("dojo_cadet", "Password123!", role="analyst", email="dojo@test.local")
    user = get_user_by_username("dojo_cadet")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Complete today's dojo via answer submission
    resp = client.post("/api/dojo/answer", json={"vuln_type": "xss", "choice_index": 1})
    assert resp.status_code == 200

    # Capability evidence for dojo_cadet should be empty
    evidence = get_capability_evidence(user["id"])
    assert len([e for e in evidence if e["is_verified"] == 1]) == 0


def test_shadow_completion_creates_unverified_manual_detection_only():
    """Completing shadow task creates is_verified=0 evidence; does NOT advance mastery above NOT_STARTED."""
    create_user("shadow_tester_2", "Password123!", role="analyst", email="st2@test.local")
    user = get_user_by_username("shadow_tester_2")

    mock_scan = {
        "scan_type": "dast",
        "target": "https://test.local",
        "vulnerabilities": [{"check": "xss", "title": "XSS Found", "severity": "high"}],
    }
    token = store_report(mock_scan, risk_score=8.0, original_content=None, user_id=user["id"], username="shadow_tester_2")

    res = complete_shadow_task(token, "xss", user["id"], "Reproduced manually with curl")
    assert res is not None

    evidence = get_capability_evidence(user["id"], vuln_type="xss", capability="manual_detection")
    assert len(evidence) == 1
    assert evidence[0]["is_verified"] == 0
    assert evidence[0]["evidence_type"] == "SELF_REPORTED"

    # Mastery state remains NOT_STARTED because no exercise_attempts exist
    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["capabilities"]["manual_detection"]["state"] == "NOT_STARTED"


def test_user_isolation_cannot_read_other_user_evidence():
    """User B cannot see User A's capability evidence."""
    create_user("user_a", "Password123!", role="analyst", email="usera@test.local")
    create_user("user_b", "Password123!", role="analyst", email="userb@test.local")
    user_a = get_user_by_username("user_a")
    user_b = get_user_by_username("user_b")

    record_capability_evidence(user_a["id"], "xss", "knowledge", "EVALUATED", "test", is_verified=0, score=0.8)

    ev_b = get_capability_evidence(user_b["id"], vuln_type="xss")
    assert len(ev_b) == 0


def test_mastery_not_started_no_attempts():
    """When zero attempts and evidence exist, all capabilities and skill level are NOT_STARTED."""
    create_user("newbie", "Password123!", role="analyst", email="newbie@test.local")
    user = get_user_by_username("newbie")

    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["skill_level"] == "NOT_STARTED"
    for cap, data in matrix["capabilities"].items():
        assert data["state"] == "NOT_STARTED"
        assert data["attempts_count"] == 0


def test_mastery_introduced_after_exercise_start_only():
    """Rule C: Starting an exercise attempt advances capability to INTRODUCED (zero evidence weight)."""
    create_user("starter", "Password123!", role="analyst", email="starter@test.local")
    user = get_user_by_username("starter")

    exercise = create_exercise("xss", "knowledge", "assessment", "XSS Basics")
    start_exercise_attempt(user["id"], exercise["id"])

    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["capabilities"]["knowledge"]["state"] == "INTRODUCED"
    assert matrix["capabilities"]["knowledge"]["verified_evidence_count"] == 0
    assert matrix["capabilities"]["knowledge"]["evidence_count"] == 0
    assert matrix["skill_level"] == "INTRODUCED"


def test_mastery_practiced_after_assessment_score_05():
    """Attempt with evaluated score >= 0.5 advances capability to PRACTICED."""
    create_user("practitioner", "Password123!", role="analyst", email="prac@test.local")
    user = get_user_by_username("practitioner")

    exercise = create_exercise(
        "sqli", "knowledge", "assessment", "SQLi Basics",
        content_json={"min_words": 10, "expected_concepts": ["escaping"]},
    )
    attempt = start_exercise_attempt(user["id"], exercise["id"])
    # 1/1 concepts = score 0.9, but let's test a moderate submission yielding >= 0.5
    complete_exercise_attempt(
        attempt["id"], user["id"],
        submission_text="Output escaping is necessary to prevent injection attacks and syntax breakout.",
    )

    matrix = compute_mastery_matrix(user["id"], "sqli")
    assert matrix["capabilities"]["knowledge"]["state"] in ("PRACTICED", "DEMONSTRATED", "MASTERED")


def test_mastery_demonstrated_after_assessment_score_08():
    """Option B: Evaluated score >= 0.8 advances capability to DEMONSTRATED (or MASTERED if recency passes)."""
    create_user("expert", "Password123!", role="analyst", email="expert@test.local")
    user = get_user_by_username("expert")

    exercise = create_exercise(
        "rce", "knowledge", "assessment", "RCE Defense",
        content_json={"min_words": 10, "expected_concepts": ["allowlist", "shell"]},
    )
    attempt = start_exercise_attempt(user["id"], exercise["id"])
    res = complete_exercise_attempt(
        attempt["id"], user["id"],
        submission_text="We must avoid shell execution and use an allowlist of arguments without passing raw user commands.",
    )
    assert res["score"] >= 0.8

    matrix = compute_mastery_matrix(user["id"], "rce")
    assert matrix["capabilities"]["knowledge"]["state"] in ("DEMONSTRATED", "MASTERED")


def test_mastery_demonstrated_after_verified_evidence():
    """Option A: Server-side verified evidence (is_verified=1) qualifies for DEMONSTRATED / MASTERED."""
    create_user("flag_hunter", "Password123!", role="analyst", email="fh@test.local")
    user = get_user_by_username("flag_hunter")

    record_capability_evidence(
        user_id=user["id"],
        vuln_type="ssrf",
        capability="lab_exploitation",
        evidence_type="VERIFIED",
        evidence_source="sandbox_verified:sb123",
        is_verified=1,
        score=1.0,
    )

    matrix = compute_mastery_matrix(user["id"], "ssrf")
    assert matrix["capabilities"]["lab_exploitation"]["state"] in ("DEMONSTRATED", "MASTERED")
    assert matrix["capabilities"]["lab_exploitation"]["verified_evidence_count"] == 1
