"""Phase 2B Test Suite: Exercise Engine Foundation & Anti-Cheat Invariants.

Validates:
1. Exercise Attempt Lifecycle & INTRODUCED State (Rule C: 0 evidence weight).
2. Multi-Capability Server-Side Evaluators for the 2 Reference Skills:
   - http_fundamentals: knowledge, recognition, manual_detection.
   - xss: knowledge, recognition, validation, lab_exploitation, impact_analysis.
   - Remediation and Reporting framework evaluators.
3. Strict Anti-Cheat Invariants:
   - Client parameter stripping (client cannot inject score, is_verified, evaluation_status).
   - Cross-user attempt isolation (User B cannot complete User A's attempt).
   - Sandbox proof verification:
     * Fake flag rejected (score=0.0, is_verified=0).
     * Missing sandbox rejected.
     * Cross-user sandbox theft rejected (User B cannot use User A's sandbox).
     * Mismatched target rejected (SQLi sandbox cannot complete XSS challenge).
     * Expired sandbox (TTL) rejected.
     * Sandbox replay / reuse rejected.
     * Valid server-side flag produces score=1.0 and is_verified=1.
4. Mastery State Machine Transitions:
   - NOT_STARTED -> INTRODUCED -> PRACTICED -> DEMONSTRATED -> MASTERED.
"""

from __future__ import annotations

import hashlib
import os
import time
import pytest
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
    compute_mastery_matrix,
    get_capability_evidence,
    save_active_sandbox_record,
    get_active_sandbox_record,
    delete_active_sandbox_record,
)
from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK, SANDBOX_ALLOWLIST
from db.exercise_engine import (
    evaluate_knowledge_submission,
    evaluate_recognition_submission,
    evaluate_detection_submission,
    evaluate_validation_submission,
    evaluate_impact_submission,
    evaluate_remediation_submission,
    evaluate_reporting_submission,
    evaluate_submission,
)


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Set up isolated test database and sandbox registry for each test."""
    test_db = str(tmp_path / "test_phase2b.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-phase2b-secret")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    # Seed reference exercises
    from seed_learning import seed
    seed()


# ── 1. Attempt Lifecycle & INTRODUCED State ─────────────────────────────────────

def test_attempt_start_sets_introduced_with_zero_evidence():
    """Starting an attempt sets INTRODUCED state with zero evidence records."""
    create_user("student1", "Password123!", role="analyst", email="s1@example.com")
    user = get_user_by_username("student1")
    user_id = user["id"]

    # Initial state must be NOT_STARTED
    matrix_before = compute_mastery_matrix(user_id, "http_fundamentals")
    assert matrix_before["capabilities"]["knowledge"]["state"] == "NOT_STARTED"
    assert matrix_before["skill_level"] == "NOT_STARTED"

    ex = get_exercises_for_skill("http_fundamentals", capability="knowledge")[0]
    attempt = start_exercise_attempt(user_id, ex["id"])

    assert attempt["result"] == "pending"
    assert attempt["evaluation_status"] == "pending"
    assert attempt["score"] is None
    assert attempt["completed_at"] is None

    # Capability must now be INTRODUCED (engagement state only)
    matrix_after = compute_mastery_matrix(user_id, "http_fundamentals")
    assert matrix_after["capabilities"]["knowledge"]["state"] == "INTRODUCED"
    assert matrix_after["capabilities"]["knowledge"]["evidence_count"] == 0

    # Evidence table must contain zero rows for this user
    evidence = get_capability_evidence(user_id, "http_fundamentals")
    assert len(evidence) == 0


# ── 2. Reference Skill 1: http_fundamentals Evaluators ─────────────────────────

def test_http_fundamentals_knowledge_evaluator():
    """Knowledge evaluator: checks depth, concept coverage, capping at 0.9, is_verified=0."""
    content = {
        "min_words": 20,
        "expected_concepts": ["verbs", "methods", "status codes", "headers", "stateless"],
    }

    # Case A: Shallow submission (< min_words)
    res_shallow = evaluate_knowledge_submission("HTTP is a protocol.", content)
    assert res_shallow["score"] == 0.2
    assert res_shallow["result"] == "failed"
    assert res_shallow["is_verified"] == 0
    assert res_shallow["evidence_type"] is None

    # Case B: Sufficient depth but no concepts
    text_noconcepts = "This is an essay discussing internet networking protocols in general without referencing the specific requirements of the assignment at all today."
    res_noconcepts = evaluate_knowledge_submission(text_noconcepts, content)
    assert res_noconcepts["score"] == 0.3
    assert res_noconcepts["result"] == "failed"

    # Case C: Full concept coverage -> score capped at 0.9, is_verified=0
    text_full = (
        "HTTP defines communication using request and response messages. Client methods or verbs such as "
        "GET and POST define operations, while three-digit status codes indicate outcomes. Critical security "
        "headers govern transport, and stateless communication requires session tokens stored in secure cookies."
    )
    res_full = evaluate_knowledge_submission(text_full, content)
    assert res_full["score"] <= 0.9
    assert res_full["score"] >= 0.8
    assert res_full["result"] == "passed"
    assert res_full["is_verified"] == 0
    assert res_full["evidence_type"] == "EVALUATED"


def test_http_fundamentals_recognition_evaluator():
    """Recognition evaluator: target identification + pattern explanation."""
    content = {
        "min_words": 15,
        "target_indicators": ["Authorization: Basic", "http://", "line 4"],
        "pattern_keywords": ["cleartext", "unencrypted", "credentials", "base64"],
    }

    # Case A: Fails to identify vulnerable location/indicator
    bad_submission = "I reviewed the traffic and everything looks completely normal without any major red flags in the system."
    res_bad = evaluate_recognition_submission(bad_submission, content)
    assert res_bad["score"] < 0.5
    assert res_bad["result"] == "failed"

    # Case B: Identifies target indicator + explains cleartext exposure
    good_submission = (
        "On line 4, the request uses Authorization: Basic over plain unencrypted http://. "
        "The base64 encoded credentials are sent in cleartext, exposing the password to network eavesdropping."
    )
    res_good = evaluate_recognition_submission(good_submission, content)
    assert res_good["score"] >= 0.8
    assert res_good["score"] <= 0.9
    assert res_good["result"] == "passed"
    assert res_good["is_verified"] == 0
    assert res_good["evidence_type"] == "EVALUATED"


def test_http_fundamentals_manual_detection_evaluator():
    """Manual detection evaluator: validates cURL command flags and extracted response artifacts."""
    content = {
        "required_commands": ["curl", "-I", "-X"],
        "expected_artifacts": ["200 OK", "Server:", "Allow:"],
    }

    # Case A: Missing flags and wrong artifacts
    res_bad = evaluate_detection_submission("ping 127.0.0.1", content)
    assert res_bad["score"] < 0.5
    assert res_bad["result"] == "failed"

    # Case B: Proper cURL command and captured headers
    good_submission = (
        "I ran: curl -I -X OPTIONS http://127.0.0.1:5000/api/status\n"
        "Output:\n"
        "HTTP/1.1 200 OK\n"
        "Server: Werkzeug/3.0\n"
        "Allow: GET, POST, OPTIONS, HEAD\n"
    )
    res_good = evaluate_detection_submission(good_submission, content)
    assert res_good["score"] >= 0.8
    assert res_good["score"] <= 0.9
    assert res_good["result"] == "passed"
    assert res_good["is_verified"] == 0


# ── 3. Reference Skill 2: xss Evaluators ───────────────────────────────────────

def test_xss_validation_evaluator():
    """Validation evaluator: checks True Positive classification and canary breakout proof."""
    content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["canary", "breakout", "alert", "unescaped"],
    }

    # Case A: Misclassified as False Positive
    bad_res = evaluate_validation_submission("This is a false positive because the scanner is lying.", content)
    assert bad_res["score"] == 0.2
    assert bad_res["result"] == "failed"

    # Case B: Confirmed True Positive with canary reflection proof
    good_res = evaluate_validation_submission(
        "Confirmed true positive. Injected unique canary token <script>alert(1)</script> into the search parameter. "
        "The reflection rendered completely unescaped in the HTML body context, proving attribute breakout and arbitrary script execution.",
        content,
    )
    assert good_res["score"] >= 0.8
    assert good_res["score"] <= 0.9
    assert good_res["result"] == "passed"
    assert good_res["is_verified"] == 0


def test_xss_impact_analysis_evaluator():
    """Impact analysis evaluator: checks CVSS v3.1 metrics and blast radius narrative."""
    content = {
        "min_words": 20,
        "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
        "impact_keywords": ["session hijacking", "cookie theft", "account takeover", "privilege escalation"],
    }

    good_submission = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (Score: 6.1 Medium)\n"
        "Technical blast radius allows attacker to execute arbitrary JavaScript in victim browser. "
        "Business impact includes session hijacking via document.cookie theft, credential phishing, "
        "and account takeover leading to administrative privilege escalation."
    )
    res = evaluate_impact_submission(good_submission, content)
    assert res["score"] >= 0.8
    assert res["score"] <= 0.9
    assert res["result"] == "passed"
    assert res["is_verified"] == 0


# ── 4. Framework Evaluators: Remediation & Reporting ───────────────────────────

def test_remediation_and_reporting_framework_evaluators():
    """Remediation and reporting evaluators are structured, capped at 0.9, and have is_verified=0."""
    # Remediation
    rem_content = {
        "defense_concepts": ["context-aware escaping", "csp", "encodeforhtml"],
        "prohibited_patterns": ["eval", "innerhtml"],
    }
    rem_bad = evaluate_remediation_submission("I fixed it using eval(escape(input)) and innerHTML = data;", rem_content)
    assert rem_bad["score"] <= 0.3
    assert rem_bad["result"] == "failed"

    rem_good = evaluate_remediation_submission(
        "Replaced direct string concatenation with context-aware escaping using encodeForHTML. "
        "Configured strict Content-Security-Policy (CSP) headers to block inline scripts.",
        rem_content,
    )
    assert rem_good["score"] >= 0.7
    assert rem_good["score"] <= 0.9
    assert rem_good["is_verified"] == 0

    # Reporting
    rep_content = {
        "min_words": 25,
        "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
    }
    rep_good = evaluate_reporting_submission(
        "## Summary\nReflected XSS in search endpoint.\n"
        "## Steps to Reproduce\n1. Visit /search?q=<script>alert(1)</script>\n"
        "## Impact\nSession hijacking and account takeover.\n"
        "## Remediation\nImplement contextual HTML entity encoding.",
        rep_content,
    )
    assert rep_good["score"] >= 0.7
    assert rep_good["score"] <= 0.9
    assert rep_good["is_verified"] == 0


# ── 5. Anti-Cheat: Client Parameter Stripping ──────────────────────────────────

def test_api_strips_client_supplied_score_and_verification():
    """Client submitting score=1.0, is_verified=1, and evaluation_status=system_verified is stripped."""
    app = create_app()
    client = app.test_client()

    create_user("cadet_cheat", "Password123!", role="analyst", email="cheat@example.com")
    user = get_user_by_username("cadet_cheat")
    user_id = user["id"]

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    ex = get_exercises_for_skill("http_fundamentals", capability="knowledge")[0]
    attempt = start_exercise_attempt(user_id, ex["id"])

    # Malicious payload trying to trick backend into recording 1.0 verified
    malicious_payload = {
        "attempt_id": attempt["id"],
        "submission_text": (
            "HTTP defines communication using request and response messages. Client methods or verbs such as "
            "GET and POST define operations, while three-digit status codes indicate outcomes. Critical security "
            "headers govern transport, and stateless communication requires session tokens stored in secure cookies."
        ),
        "score": 1.0,
        "is_verified": 1,
        "evaluation_status": "system_verified",
        "result": "passed",
    }

    resp = client.post("/api/learning/attempt/complete", json=malicious_payload)
    assert resp.status_code == 200
    data = resp.get_json()

    # The server must evaluate independently: score must NOT be 1.0, and evidence must NOT be verified!
    assert data["score"] <= 0.9
    assert data["attempt"]["score"] <= 0.9
    assert data["attempt"]["evaluation_status"] == "auto_evaluated"

    evidence = get_capability_evidence(user_id, "http_fundamentals", capability="knowledge")
    assert len(evidence) == 1
    assert evidence[0]["is_verified"] == 0
    assert evidence[0]["score"] <= 0.9


# ── 6. Anti-Cheat: Cross-User Attempt Isolation (D-06) ─────────────────────────

def test_cross_user_attempt_isolation():
    """User B cannot complete or tamper with User A's exercise attempt."""
    app = create_app()
    client = app.test_client()

    create_user("user_a", "Password123!", role="analyst", email="ua@example.com")
    create_user("user_b", "Password123!", role="analyst", email="ub@example.com")
    user_a = get_user_by_username("user_a")
    user_b = get_user_by_username("user_b")

    ex = get_exercises_for_skill("http_fundamentals", capability="knowledge")[0]
    attempt_a = start_exercise_attempt(user_a["id"], ex["id"])

    # Authenticate as User B
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_b["id"])
        sess["_fresh"] = True

    # User B attempts to complete User A's attempt
    resp = client.post("/api/learning/attempt/complete", json={
        "attempt_id": attempt_a["id"],
        "submission_text": "Valid text explaining HTTP verbs headers and status codes in stateless systems with cookies.",
    })
    assert resp.status_code == 403
    assert "access denied" in resp.get_json()["error"].lower()

    # Direct database call also raises PermissionError
    with pytest.raises(PermissionError):
        complete_exercise_attempt(attempt_a["id"], user_id=user_b["id"], submission_text="Test")


# ── 7. Anti-Cheat: Authoritative Sandbox Verification & Proof Integrity ───────

def test_sandbox_verification_security_boundaries():
    """Rigorous tests proving that score=1.0 and is_verified=1 are impossible without valid sandbox proof."""
    create_user("lab_user", "Password123!", role="analyst", email="lab@example.com")
    create_user("intruder", "Password123!", role="analyst", email="intruder@example.com")
    lab_user = get_user_by_username("lab_user")
    intruder = get_user_by_username("intruder")

    lab_ex = get_exercises_for_skill("xss", capability="lab_exploitation")[0]
    attempt = start_exercise_attempt(lab_user["id"], lab_ex["id"])

    # Boundary 1: No sandbox_id provided -> fails, score=0.0
    res_no_sb = complete_exercise_attempt(attempt["id"], lab_user["id"], submission_text="FLAG{fake}")
    assert res_no_sb["score"] == 0.0
    assert res_no_sb["result"] == "failed"
    ev_none = get_capability_evidence(lab_user["id"], "xss", capability="lab_exploitation")
    assert len(ev_none) == 0

    # Start an attempt for lab_user to test active sandbox cases
    attempt2 = start_exercise_attempt(lab_user["id"], lab_ex["id"])

    # Register an active sandbox in server registry
    sb_id = "test_sb_xss_12345"
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_id] = {
            "id": sb_id,
            "user_id": lab_user["id"],
            "vuln_type": "xss",
            "name": "OWASP Juice Shop — XSS Laboratory",
            "status": "running",
            "completed": False,
            "expires_at": time.time() + 3600,
        }

    # Boundary 2: Fake flag submitted -> fails, score=0.0
    res_bad_flag = complete_exercise_attempt(
        attempt2["id"],
        lab_user["id"],
        metadata={"sandbox_id": sb_id, "flag": "FLAG{wrong_guess}"},
    )
    assert res_bad_flag["score"] == 0.0
    assert res_bad_flag["result"] == "failed"

    # Boundary 3: Cross-user sandbox theft (Intruder attempts to use lab_user's sandbox)
    attempt_intruder = start_exercise_attempt(intruder["id"], lab_ex["id"])
    res_theft = complete_exercise_attempt(
        attempt_intruder["id"],
        intruder["id"],
        metadata={"sandbox_id": sb_id, "flag": SANDBOX_ALLOWLIST["xss"]["proof_flag"]},
    )
    assert res_theft["score"] == 0.0
    assert "ownership mismatch" in res_theft["notes"].lower()

    # Boundary 4: Target mismatch (Register SQLi sandbox, try to complete XSS attempt)
    sb_sqli = "test_sb_sqli_67890"
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_sqli] = {
            "id": sb_sqli,
            "user_id": lab_user["id"],
            "vuln_type": "sqli",
            "name": "DVWA SQLi Challenge",
            "status": "running",
            "completed": False,
            "expires_at": time.time() + 3600,
        }
    attempt3 = start_exercise_attempt(lab_user["id"], lab_ex["id"])
    res_mismatch = complete_exercise_attempt(
        attempt3["id"],
        lab_user["id"],
        metadata={"sandbox_id": sb_sqli, "flag": SANDBOX_ALLOWLIST["sqli"]["proof_flag"]},
    )
    assert res_mismatch["score"] == 0.0
    assert "target mismatch" in res_mismatch["notes"].lower()

    # Boundary 5: Expired sandbox (TTL exceeded)
    sb_expired = "test_sb_expired_11111"
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_expired] = {
            "id": sb_expired,
            "user_id": lab_user["id"],
            "vuln_type": "xss",
            "name": "OWASP Juice Shop — XSS Laboratory",
            "status": "running",
            "completed": False,
            "expires_at": time.time() - 10,  # Expired 10 seconds ago
        }
    attempt4 = start_exercise_attempt(lab_user["id"], lab_ex["id"])
    res_expired = complete_exercise_attempt(
        attempt4["id"],
        lab_user["id"],
        metadata={"sandbox_id": sb_expired, "flag": SANDBOX_ALLOWLIST["xss"]["proof_flag"]},
    )
    assert res_expired["score"] == 0.0
    assert "expired" in res_expired["notes"].lower()

    # Boundary 6: Valid Authentic Server-Side Verification -> Score=1.0 and is_verified=1!
    attempt_success = start_exercise_attempt(lab_user["id"], lab_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["xss"]["proof_flag"]
    res_valid = complete_exercise_attempt(
        attempt_success["id"],
        lab_user["id"],
        metadata={"sandbox_id": sb_id, "flag": correct_flag},
    )
    assert res_valid["score"] == 1.0
    assert res_valid["result"] == "passed"
    assert res_valid["evaluation_status"] == "system_verified"

    # Verify evidence was recorded as VERIFIED with score 1.0
    verified_ev = get_capability_evidence(lab_user["id"], "xss", capability="lab_exploitation")
    assert len(verified_ev) == 1
    assert verified_ev[0]["is_verified"] == 1
    assert verified_ev[0]["score"] == 1.0
    assert verified_ev[0]["evidence_type"] == "VERIFIED"

    # Boundary 7: Replay / Reuse prevention (Cannot complete using the same sandbox again)
    attempt_replay = start_exercise_attempt(lab_user["id"], lab_ex["id"])
    res_replay = complete_exercise_attempt(
        attempt_replay["id"],
        lab_user["id"],
        metadata={"sandbox_id": sb_id, "flag": correct_flag},
    )
    assert res_replay["score"] == 0.0
    assert "already been completed" in res_replay["notes"].lower() or "not active" in res_replay["notes"].lower()


# ── 8. Mastery State Machine Progression ───────────────────────────────────────

def test_mastery_state_machine_progression():
    """Verifies state machine: NOT_STARTED -> INTRODUCED -> PRACTICED -> DEMONSTRATED -> MASTERED."""
    create_user("mastery_learner", "Password123!", role="analyst", email="m_learner@example.com")
    user = get_user_by_username("mastery_learner")
    user_id = user["id"]

    # 1. Initially NOT_STARTED
    m0 = compute_mastery_matrix(user_id, "http_fundamentals")
    assert m0["capabilities"]["knowledge"]["state"] == "NOT_STARTED"

    # 2. Advance to INTRODUCED
    ex = get_exercises_for_skill("http_fundamentals", capability="knowledge")[0]
    att1 = start_exercise_attempt(user_id, ex["id"])
    m1 = compute_mastery_matrix(user_id, "http_fundamentals")
    assert m1["capabilities"]["knowledge"]["state"] == "INTRODUCED"

    # 3. Complete with score 0.6 -> advances to PRACTICED (score >= 0.5)
    text_practiced = (
        "In this introductory overview of HTTP fundamentals, we examine how client requests and server responses interact over the network. "
        "Basic HTTP methods include GET and POST, and three-digit status codes report outcomes."
    )
    res1 = complete_exercise_attempt(att1["id"], user_id, submission_text=text_practiced)
    assert res1["score"] >= 0.5
    assert res1["score"] < 0.8
    m2 = compute_mastery_matrix(user_id, "http_fundamentals")
    assert m2["capabilities"]["knowledge"]["state"] == "PRACTICED"

    # 4. Complete another attempt with high score (0.9) -> advances to DEMONSTRATED & MASTERED
    att2 = start_exercise_attempt(user_id, ex["id"])
    text_demo = (
        "HTTP defines communication using request and response messages. Client methods or verbs such as "
        "GET and POST define operations, while three-digit status codes indicate outcomes. Critical security "
        "headers govern transport, and stateless communication requires session tokens stored in secure cookies."
    )
    res2 = complete_exercise_attempt(att2["id"], user_id, submission_text=text_demo)
    assert res2["score"] >= 0.8
    m3 = compute_mastery_matrix(user_id, "http_fundamentals")
    # Score >= 0.8 satisfies Option B for DEMONSTRATED; and recency <= 90 days with no failures satisfies MASTERED
    assert m3["capabilities"]["knowledge"]["state"] in ("DEMONSTRATED", "MASTERED")


# ── 9. Anti-Stuffing & Structural Integrity Hardening ─────────────────────────

def test_evaluator_rejects_keyword_stuffing_and_repetition():
    """Knowledge and recognition evaluators reject keyword stuffing and repetition padding."""
    content = {
        "min_words": 30,
        "expected_concepts": ["verbs", "methods", "status codes", "headers", "stateless"],
    }

    # Case A: Repetitive word stuffing (repeating the same 4 words to reach 32 words)
    # Lexical diversity = 4 / 32 = 0.125 < 0.45
    stuffed_text = "verbs methods headers status " * 8
    res_stuffed = evaluate_knowledge_submission(stuffed_text, content)
    assert res_stuffed["score"] == 0.2
    assert res_stuffed["result"] == "failed"
    assert "anti-stuffing violation" in res_stuffed["notes"].lower()

    # Case B: Recognition evaluator rejecting keyword repetition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["Authorization: Basic"],
        "pattern_keywords": ["cleartext", "unencrypted"],
    }
    stuffed_rec = "Authorization: Basic " + ("cleartext " * 15)
    res_stuffed_rec = evaluate_recognition_submission(stuffed_rec, rec_content)
    assert res_stuffed_rec["score"] == 0.2
    assert res_stuffed_rec["result"] == "failed"
    assert "anti-stuffing violation" in res_stuffed_rec["notes"].lower()


# ── 10. Sandbox Persistence & Restart Simulation ──────────────────────────────

def test_sandbox_restart_wipe_fails_closed_404_and_survives_worker_recycle():
    """Authoritative test for sandbox persistence across worker restart and cold wipe."""
    app = create_app()
    client = app.test_client()

    create_user("restart_user", "Password123!", role="analyst", email="restart@example.com")
    user = get_user_by_username("restart_user")
    user_id = user["id"]

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    # 1. Launch a sandbox via API -> automatically persisted to SQLite
    launch_res = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    assert launch_res.status_code == 201
    sb_id = launch_res.get_json()["sandbox"]["id"]

    # Verify sandbox is present in SQLite
    db_rec = get_active_sandbox_record(sb_id)
    assert db_rec is not None
    assert db_rec["status"] == "running"
    assert db_rec["user_id"] == user_id

    # 2. Simulate Gunicorn Worker Recycle: Wipe only in-memory dict
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()
        assert sb_id not in _ACTIVE_SANDBOXES

    # Attempt verification -> backend recovers state from SQLite and validates!
    correct_flag = SANDBOX_ALLOWLIST["xss"]["proof_flag"]
    recycle_res = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": correct_flag})
    assert recycle_res.status_code == 200
    assert recycle_res.get_json()["verified"] is True

    # 3. Simulate Complete Cold Reboot / Ephemeral Wipe:
    # Delete the record from SQLite and clear memory
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    # Now attempt verification of the wiped sandbox -> MUST return 404 fail-closed!
    wiped_res = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": correct_flag})
    assert wiped_res.status_code == 404
    wiped_data = wiped_res.get_json()
    assert wiped_data["ok"] is False
    assert "sandbox not found" in wiped_data["error"].lower()

    # Direct database / exercise engine call on wiped sandbox also returns 0.0 fail-closed
    lab_ex = get_exercises_for_skill("xss", capability="lab_exploitation")[0]
    att = start_exercise_attempt(user_id, lab_ex["id"])
    att_res = complete_exercise_attempt(
        att["id"],
        user_id,
        metadata={"sandbox_id": sb_id, "flag": correct_flag},
    )
    assert att_res["score"] == 0.0
    assert att_res["result"] == "failed"
    assert att_res["attempt"]["evidence_id"] is None
    assert "not found" in att_res["notes"].lower()
    # Ensure zero evidence records inserted for wiped/failed sandbox
    ev_wiped = get_capability_evidence(user_id, "xss", capability="lab_exploitation")
    # Only the first successful recycle attempt created evidence (from step 2), no new verified evidence was added
    assert len(ev_wiped) == 1


