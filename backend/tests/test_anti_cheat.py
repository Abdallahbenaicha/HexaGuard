"""Anti-Cheat and Trust Boundary Test Suite (test_anti_cheat.py).

Verifies non-negotiable rules:
- SEC-01: Client cannot inject verified=True into shadow task API.
- D-07: Client cannot supply score, evaluation_status, or result to attempt completion API.
- Backend-only evaluator derives score from content_json and submission_text.
- Score is capped at 0.9 for assessment submissions (1.0 reserved for VERIFIED).
- Server-side sandbox verification is the exclusive source for is_verified=1.
- M-2: 90-day decay from MASTERED to DEMONSTRATED.
- M-3: Blocking failure (<0.3 in 30 days) caps at DEMONSTRATED unless superseded by a later success.
- Remediation capability creates no evidence and stays NOT_STARTED in Phase 1.
"""

from datetime import datetime, timedelta, timezone
import pytest
from database import (
    init_db,
    create_user,
    get_user_by_username,
    store_report,
    get_shadow_tasks_for_report,
    get_user_skill_ledger,
    create_exercise,
    start_exercise_attempt,
    get_attempt,
    evaluate_assessment_submission,
    record_capability_evidence,
    compute_mastery_matrix,
    _get_db,
)
from app import create_app


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_anti_cheat.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-anti-cheat-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_client_verified_true_is_rejected_from_shadow_api():
    """SEC-01: Passing verified=True in shadow complete payload is ignored; recorded as self-reported only."""
    create_user("shadow_tester", "Password123!", role="analyst", email="shadow@test.local")
    user = get_user_by_username("shadow_tester")

    mock_scan = {
        "scan_type": "dast",
        "target": "https://test.local",
        "vulnerabilities": [{"check": "xss", "title": "XSS Vulnerability", "severity": "high"}],
    }
    token = store_report(
        result=mock_scan,
        risk_score=7.5,
        original_content=None,
        user_id=user["id"],
        username="shadow_tester",
    )

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Client maliciously attempts to send verified=True and is_verified=1
    resp = client.post(
        f"/api/reports/{token}/shadow/xss/complete",
        json={"notes": "Manual verification notes", "verified": True, "is_verified": 1, "status": "completed_verified"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["task"]["status"] == "completed_self_reported"

    # Verify skill ledger is practiced_self_reported, NEVER practiced_verified
    ledger = get_user_skill_ledger(user["id"])
    xss_entry = next(i for i in ledger if i["vuln_type"] == "xss")
    assert xss_entry["status"] == "practiced_self_reported"


def test_client_score_submission_is_ignored():
    """D-07: Client passing score=1.0 on attempt completion has its score ignored; backend evaluates."""
    create_user("cheater_1", "Password123!", role="analyst", email="cheater1@test.local")
    user = get_user_by_username("cheater_1")

    exercise = create_exercise(
        vuln_type="xss",
        capability="knowledge",
        exercise_type="assessment",
        title_en="XSS Fundamentals Assessment",
        content_json={"min_words": 50, "expected_concepts": ["input", "context", "escaping"]},
    )

    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Client submits 3 words with a claimed score of 1.0
    resp = client.post(
        "/api/learning/attempt/complete",
        json={"attempt_id": attempt["id"], "submission_text": "I solved it", "score": 1.0, "evaluation_status": "human_evaluated"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    # Word count is 3 < 50, backend auto-evaluator computes 0.2
    assert data["score"] == 0.2
    assert data["score"] != 1.0

    # Verify in DB
    db_attempt = get_attempt(attempt["id"])
    assert db_attempt["score"] == 0.2


def test_client_evaluation_status_submission_is_ignored():
    """D-07: Client cannot declare evaluation_status='human_evaluated'."""
    create_user("cheater_2", "Password123!", role="analyst", email="cheater2@test.local")
    user = get_user_by_username("cheater_2")

    exercise = create_exercise(
        vuln_type="sqli",
        capability="knowledge",
        exercise_type="assessment",
        title_en="SQLi Assessment",
        content_json={"min_words": 20, "expected_concepts": ["parameters"]},
    )
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post(
        "/api/learning/attempt/complete",
        json={
            "attempt_id": attempt["id"],
            "submission_text": "Short submission",
            "evaluation_status": "human_evaluated",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["evaluation_status"] == "auto_evaluated"


def test_client_cannot_dictate_evaluation_status():
    """Verify client cannot dictate score, evaluation_status, result, is_verified, or evidence_type."""
    from database import get_capability_evidence
    create_user("status_cheater", "Password123!", role="analyst", email="status_cheater@test.local")
    user = get_user_by_username("status_cheater")

    exercise = create_exercise(
        vuln_type="sqli",
        capability="knowledge",
        exercise_type="assessment",
        title_en="SQLi Assessment Defense Test",
        content_json={"min_words": 50, "expected_concepts": ["prepared", "parameterized"]},
    )
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Client tries to dictate every evaluation and verification field
    resp = client.post(
        "/api/learning/attempt/complete",
        json={
            "attempt_id": attempt["id"],
            "submission_text": "Bad attempt with no concepts",
            "score": 1.0,
            "evaluation_status": "manually_approved",
            "result": "passed",
            "is_verified": 1,
            "evidence_type": "VERIFIED_EXPLOIT",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    # Server-derived values must completely override client input
    assert data["evaluation_status"] == "auto_evaluated"
    assert data["evaluation_status"] != "manually_approved"
    assert data["score"] == 0.2  # Length < 50, concepts missing -> 0.2
    assert data["score"] != 1.0
    assert data["result"] == "failed"
    assert data["result"] != "passed"

    # Verify database attempt row
    db_attempt = get_attempt(attempt["id"])
    assert db_attempt["evaluation_status"] == "auto_evaluated"
    assert db_attempt["score"] == 0.2
    assert db_attempt["result"] == "failed"

    # Verify no verified evidence was created
    ev = get_capability_evidence(user["id"], "sqli", "knowledge")
    assert not any(e["is_verified"] == 1 for e in ev)


def test_backend_evaluator_computes_score_not_client():
    """Valid submission with all expected concepts covered scores 0.9 via backend auto-evaluator."""
    create_user("student_1", "Password123!", role="analyst", email="student1@test.local")
    user = get_user_by_username("student_1")

    exercise = create_exercise(
        vuln_type="xss",
        capability="knowledge",
        exercise_type="assessment",
        title_en="XSS Prevention Assessment",
        content_json={
            "min_words": 10,
            "expected_concepts": ["encoding", "sanitization", "csp"],
        },
    )
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    submission = "Proper context encoding, strict HTML sanitization, and Content Security Policy (csp) mitigate XSS thoroughly."
    resp = client.post(
        "/api/learning/attempt/complete",
        json={"attempt_id": attempt["id"], "submission_text": submission},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["score"] == 0.9
    assert data["result"] == "passed"


def test_sandbox_api_sets_is_verified_server_side_only():
    """Invalid flag fails sandbox verification; only server-verified flag sets is_verified=1."""
    create_user("sandbox_anti", "Password123!", role="analyst", email="sandbox_anti@test.local")
    user = get_user_by_username("sandbox_anti")

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Launch sandbox
    launch_resp = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    assert launch_resp.status_code == 201
    sb_id = launch_resp.get_json()["sandbox"]["id"]

    # Submit bad flag
    bad_resp = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": "FLAG{wrong_flag}"})
    assert bad_resp.status_code == 400
    assert bad_resp.get_json()["verified"] is False

    # Submit valid flag
    good_resp = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": "FLAG{xss_dom_reflection_conquered_2026}"})
    assert good_resp.status_code == 200
    assert good_resp.get_json()["verified"] is True

    # Verify is_verified=1 evidence exists and capability reached DEMONSTRATED / MASTERED
    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["capabilities"]["lab_exploitation"]["state"] in ("DEMONSTRATED", "MASTERED")
    assert matrix["capabilities"]["lab_exploitation"]["verified_evidence_count"] >= 1


def test_assessment_auto_evaluator_score_capped_at_09():
    """evaluate_assessment_submission returns at most 0.9, never 1.0 (reserved for VERIFIED)."""
    text = (
        "SQL injection occurs when untrusted input concatenates into raw database commands. "
        "To mitigate this, parameterization, prepared statements, and ORM abstractions must always be used. "
        "Input validation provides defense in depth alongside least privilege database users."
    )
    score, _ = evaluate_assessment_submission(
        submission_text=text,
        content_json={"min_words": 10, "expected_concepts": ["parameterization", "prepared statements", "least privilege"]},
    )
    assert score <= 0.9
    assert score >= 0.8


def test_mastery_decay_after_90_days():
    """M-2: Qualifying verified evidence older than 90 days decays from MASTERED to DEMONSTRATED."""
    create_user("decay_user", "Password123!", role="analyst", email="decay@test.local")
    user = get_user_by_username("decay_user")

    now = datetime.now(timezone.utc)
    old_date = _iso(now - timedelta(days=95))

    # Insert verified evidence directly with old timestamp
    db = _get_db()
    db.execute(
        "INSERT INTO skill_capability_evidence "
        "(user_id, vuln_type, capability, evidence_type, evidence_source, is_verified, score, created_at) "
        "VALUES (?, 'xss', 'lab_exploitation', 'VERIFIED', 'test', 1, 1.0, ?)",
        (user["id"], old_date),
    )
    db.commit()

    matrix = compute_mastery_matrix(user["id"], "xss")
    # State is DEMONSTRATED, not MASTERED (95 days > 90 days)
    assert matrix["capabilities"]["lab_exploitation"]["state"] == "DEMONSTRATED"


def test_mastered_restored_after_qualifying_success_post_failure():
    """D-03 / M-3: A subsequent success supersedes an earlier failure within 30 days, restoring MASTERED."""
    create_user("m3_restored_user", "Password123!", role="analyst", email="m3_restored@test.local")
    user = get_user_by_username("m3_restored_user")

    now = datetime.now(timezone.utc)
    day1 = _iso(now - timedelta(days=10))
    day2 = _iso(now - timedelta(days=5))
    day3 = _iso(now - timedelta(days=1))

    exercise = create_exercise("xss", "knowledge", "assessment", "XSS Knowledge")

    db = _get_db()
    # Day 1: Success (score 0.95)
    db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, score, evaluation_status, result) "
        "VALUES (?, ?, 'xss', 'knowledge', 1, ?, ?, 0.95, 'auto_evaluated', 'passed')",
        (user["id"], exercise["id"], day1, day1),
    )
    # Day 2: Failure (score 0.20)
    db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, score, evaluation_status, result) "
        "VALUES (?, ?, 'xss', 'knowledge', 2, ?, ?, 0.20, 'auto_evaluated', 'failed')",
        (user["id"], exercise["id"], day2, day2),
    )
    # Day 3: Qualifying success post failure (score 0.85)
    db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, score, evaluation_status, result) "
        "VALUES (?, ?, 'xss', 'knowledge', 3, ?, ?, 0.85, 'auto_evaluated', 'passed')",
        (user["id"], exercise["id"], day3, day3),
    )
    db.commit()

    matrix = compute_mastery_matrix(user["id"], "xss")
    # Day 3 success > Day 2 failure: M-3 passes, state is MASTERED
    assert matrix["capabilities"]["knowledge"]["state"] == "MASTERED"


def test_mastered_blocked_when_failure_is_most_recent():
    """D-03 / M-3: Unsuperseded failure (<0.3 within 30 days) caps capability state at DEMONSTRATED."""
    create_user("m3_blocked_user", "Password123!", role="analyst", email="m3_blocked@test.local")
    user = get_user_by_username("m3_blocked_user")

    now = datetime.now(timezone.utc)
    day1 = _iso(now - timedelta(days=10))
    day2 = _iso(now - timedelta(days=2))

    exercise = create_exercise("sqli", "knowledge", "assessment", "SQLi Knowledge")

    db = _get_db()
    # Day 1: Success (score 0.90)
    db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, score, evaluation_status, result) "
        "VALUES (?, ?, 'sqli', 'knowledge', 1, ?, ?, 0.90, 'auto_evaluated', 'passed')",
        (user["id"], exercise["id"], day1, day1),
    )
    # Day 2: Failure with no subsequent success (score 0.15)
    db.execute(
        "INSERT INTO exercise_attempts "
        "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, score, evaluation_status, result) "
        "VALUES (?, ?, 'sqli', 'knowledge', 2, ?, ?, 0.15, 'auto_evaluated', 'failed')",
        (user["id"], exercise["id"], day2, day2),
    )
    db.commit()

    matrix = compute_mastery_matrix(user["id"], "sqli")
    # M-3 blocks MASTERED because failure is unsuperseded. State is DEMONSTRATED.
    assert matrix["capabilities"]["knowledge"]["state"] == "DEMONSTRATED"


def test_no_remediation_evidence_created_in_phase1():
    """Remediation capability produces zero evidence and remains NOT_STARTED in Phase 1."""
    create_user("phase1_user", "Password123!", role="analyst", email="phase1@test.local")
    user = get_user_by_username("phase1_user")

    matrix = compute_mastery_matrix(user["id"], "xss")
    assert matrix["capabilities"]["remediation"]["state"] == "NOT_STARTED"
    assert matrix["capabilities"]["remediation"]["evidence_count"] == 0
