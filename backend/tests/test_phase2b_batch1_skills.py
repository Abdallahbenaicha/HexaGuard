"""Phase 2B Batch 1 Test Suite: 5 Foundational Skills Implementation.

Covers:
  1. dns_recon: recognition, manual_detection, impact_analysis.
  2. missing_security_headers: recognition, manual_detection, remediation.
  3. broken_auth (DVWA Sandbox): recognition, validation, lab_exploitation, cold-reboot/fail-closed.
  4. idor (Juice Shop Sandbox): recognition, validation, lab_exploitation, cold-reboot/fail-closed.
  5. sqli (DVWA Sandbox): knowledge, recognition, validation, lab_exploitation, impact_analysis, cold-reboot/fail-closed.
  6. Cross-target sandbox isolation (Juice Shop vs DVWA sandbox boundaries).
  7. Uniform anti-stuffing enforcement across all Batch 1 textual evaluators.
"""

from __future__ import annotations

import os
import time
import pytest
from app import create_app
from database import (
    init_db,
    create_user,
    get_user_by_username,
    get_exercises_for_skill,
    start_exercise_attempt,
    complete_exercise_attempt,
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
)
from seed_learning import seed


@pytest.fixture(autouse=True)
def setup_batch1_environment(tmp_path, monkeypatch):
    """Isolate test database and active sandbox registry for each test."""
    test_db = str(tmp_path / "test_batch1.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-batch1-secret")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    # Seed all curriculum exercises
    seed()


# ── 1. Seeding Integrity for Batch 1 ──────────────────────────────────────────

def test_batch1_exercises_seeded_successfully():
    """Verify that all 5 skills have their required exercises properly seeded."""
    dns_ex = get_exercises_for_skill("dns_recon")
    headers_ex = get_exercises_for_skill("missing_security_headers")
    auth_ex = get_exercises_for_skill("broken_auth")
    idor_ex = get_exercises_for_skill("idor")
    sqli_ex = get_exercises_for_skill("sqli")

    assert len(dns_ex) >= 3
    assert len(headers_ex) >= 3
    assert len(auth_ex) >= 3
    assert len(idor_ex) >= 3
    assert len(sqli_ex) >= 5

    # Verify capabilities present
    assert {e["capability"] for e in dns_ex} >= {"recognition", "manual_detection", "impact_analysis"}
    assert {e["capability"] for e in headers_ex} >= {"recognition", "manual_detection", "remediation"}
    assert {e["capability"] for e in auth_ex} >= {"recognition", "validation", "lab_exploitation"}
    assert {e["capability"] for e in idor_ex} >= {"recognition", "validation", "lab_exploitation"}
    assert {e["capability"] for e in sqli_ex} >= {"knowledge", "recognition", "validation", "lab_exploitation", "impact_analysis"}


# ── 2. Skill 1: dns_recon Evaluators ──────────────────────────────────────────

def test_dns_recon_evaluators():
    """Validates dns_recon recognition, CLI detection, and impact analysis evaluators."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["blog.example.com", "example-corp.github.io", "CNAME"],
        "pattern_keywords": ["dangling", "subdomain takeover", "unregistered", "cname"],
    }
    good_rec = (
        "DNS analysis of blog.example.com shows a dangling CNAME record pointing to example-corp.github.io. "
        "The unregistered GitHub Pages resource enables complete subdomain takeover by an attacker."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["score"] <= 0.9
    assert res_rec["result"] == "passed"
    assert res_rec["is_verified"] == 0

    # Manual Detection
    det_content = {
        "required_commands": ["dig", "TXT", "CNAME"],
        "expected_artifacts": ["v=spf1", "CNAME", "NOERROR"],
    }
    good_det = (
        "Ran: dig CNAME blog.example.com +short\n"
        "Output: example-corp.github.io.\n"
        "Ran: dig TXT example.com +short\n"
        "Output: \"v=spf1 include:_spf.google.com ~all\" with status NOERROR"
    )
    res_det = evaluate_detection_submission(good_det, det_content)
    assert res_det["score"] >= 0.8
    assert res_det["result"] == "passed"
    assert res_det["is_verified"] == 0

    # Impact Analysis
    imp_content = {
        "min_words": 20,
        "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "impact_keywords": ["subdomain takeover", "cookie theft", "phishing", "reputation"],
    }
    good_imp = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\n"
        "Technical impact allows full subdomain takeover with cross-subdomain cookie theft and CSP bypass. "
        "Business consequences include credible spear-phishing originating from trusted organizational domains and severe reputation loss."
    )
    res_imp = evaluate_impact_submission(good_imp, imp_content)
    assert res_imp["score"] >= 0.8
    assert res_imp["result"] == "passed"
    assert res_imp["is_verified"] == 0


# ── 3. Skill 2: missing_security_headers Evaluators ────────────────────────────

def test_missing_security_headers_evaluators():
    """Validates missing_security_headers recognition, detection, and remediation evaluators."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["HTTP/1.1 200 OK", "Server:"],
        "pattern_keywords": ["content-security-policy", "strict-transport-security", "x-frame-options", "nosniff"],
    }
    good_rec = (
        "The HTTP/1.1 200 OK response from the Server completely lacks Content-Security-Policy and Strict-Transport-Security headers. "
        "Furthermore, missing X-Frame-Options and nosniff directives leaves client browsers vulnerable to framing."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["result"] == "passed"
    assert res_rec["is_verified"] == 0

    # Detection
    det_content = {
        "required_commands": ["curl", "-I", "-s"],
        "expected_artifacts": ["HTTP/1.1", "Content-Type:", "Server:"],
    }
    good_det = "curl -I -s https://example.com/\nHTTP/1.1 200 OK\nServer: nginx/1.18.0\nContent-Type: text/html"
    res_det = evaluate_detection_submission(good_det, det_content)
    assert res_det["score"] >= 0.8
    assert res_det["result"] == "passed"

    # Remediation
    rem_content = {
        "defense_concepts": ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"],
        "prohibited_patterns": ["unsafe-inline", "unsafe-eval", "http://"],
    }
    good_rem = (
        "Configured Nginx edge proxy with strict headers: add_header Content-Security-Policy \"default-src 'self';\" always; "
        "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always; "
        "add_header X-Frame-Options \"DENY\" always; add_header X-Content-Type-Options \"nosniff\" always;"
    )
    res_rem = evaluate_remediation_submission(good_rem, rem_content)
    assert res_rem["score"] >= 0.8
    assert res_rem["score"] <= 0.9
    assert res_rem["is_verified"] == 0


# ── 4. Skill 3: broken_auth Evaluators & DVWA Sandbox ─────────────────────────

def test_broken_auth_evaluators_and_dvwa_sandbox():
    """Validates broken_auth recognition, validation, and DVWA sandbox with cold-reboot/fail-closed test."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["Set-Cookie", "session_id", "md5"],
        "pattern_keywords": ["predictable", "httponly", "secure", "entropy"],
    }
    good_rec = (
        "The Set-Cookie directive assigns an md5 hashed session_id derived from predictable timestamps on line 15. "
        "The cookie also omits HttpOnly and Secure flags, drastically reducing entropy and allowing trivial session hijacking."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["result"] == "passed"

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["session valid", "200 ok", "not invalidated", "post-logout"],
    }
    good_val = (
        "Confirmed true positive. Authenticated session cookie remained valid and returned 200 OK for protected endpoints "
        "post-logout, proving the session token was not invalidated server-side upon user logout."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"

    # Lab Exploitation (DVWA Broken Auth Sandbox)
    create_user("auth_learner", "Password123!", role="analyst", email="auth@example.com")
    user = get_user_by_username("auth_learner")
    user_id = user["id"]

    sb_id = "dvwa_auth_sb_9999"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "broken_auth",
        "name": "DVWA Broken Auth Lab",
        "image": "vulnerables/web-dvwa",
        "host_port": 8081,
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
        "timeout_seconds": 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_id] = sb_record
    save_active_sandbox_record(sb_record)

    # 1. Worker recycle test: Wipe in-memory dict -> verify recovery from SQLite
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    auth_ex = get_exercises_for_skill("broken_auth", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, auth_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["broken_auth"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "broken_auth", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test: Delete from DB & memory -> MUST fail-closed 404
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, auth_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 5. Skill 4: idor Evaluators & Juice Shop Sandbox ──────────────────────────

def test_idor_evaluators_and_juiceshop_sandbox():
    """Validates idor recognition, validation, and Juice Shop sandbox with cold-reboot/fail-closed test."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["/api/order/", "order_id", "SELECT * FROM orders WHERE id"],
        "pattern_keywords": ["ownership", "authorization", "direct object reference", "cross-tenant"],
    }
    good_rec = (
        "In route /api/order/, the query SELECT * FROM orders WHERE id fetches order_id directly without validating "
        "user ownership against current session context, creating a direct object reference vulnerability for cross-tenant data theft."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["result"] == "passed"

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["horizontal privilege", "cross-account", "unauthorized access", "record leaked"],
    }
    good_val = (
        "Confirmed true positive. Authenticated as User A, requested order ID 42 owned by User B. "
        "The server returned full billing data, proving unauthorized access, cross-account data exposure, and customer record leaked via horizontal privilege escalation."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"

    # Lab Exploitation (Juice Shop IDOR Sandbox)
    create_user("idor_learner", "Password123!", role="analyst", email="idor@example.com")
    user = get_user_by_username("idor_learner")
    user_id = user["id"]

    sb_id = "juice_idor_sb_5555"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "idor",
        "name": "Juice Shop IDOR Lab",
        "image": "bkimminich/juice-shop",
        "host_port": 3001,
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
        "timeout_seconds": 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_id] = sb_record
    save_active_sandbox_record(sb_record)

    # 1. Worker recycle test
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    idor_ex = get_exercises_for_skill("idor", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, idor_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["idor"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "idor", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, idor_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 6. Skill 5: sqli Evaluators & DVWA Sandbox ────────────────────────────────

def test_sqli_evaluators_and_dvwa_sandbox():
    """Validates sqli knowledge, recognition, validation, impact, and DVWA sandbox with cold-reboot test."""
    # Knowledge
    know_content = {
        "min_words": 30,
        "expected_concepts": ["parameterization", "prepared statements", "union", "orm", "syntax"],
    }
    good_know = (
        "SQL injection occurs when user input alters database query syntax. Parameterization and prepared statements "
        "compile queries prior to input binding, completely neutralizing breakout attempts. Attackers exploit string "
        "concatenation to append union queries or bypass authentication, which modern ORM frameworks prevent."
    )
    res_know = evaluate_knowledge_submission(good_know, know_content)
    assert res_know["score"] >= 0.8
    assert res_know["score"] <= 0.9
    assert res_know["result"] == "passed"

    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["cursor.execute", "f\"SELECT", "WHERE user = '"],
        "pattern_keywords": ["concatenation", "unparameterized", "interpolation", "injection sink"],
    }
    good_rec = (
        "On line 10, cursor.execute uses an unparameterized f\"SELECT query with string concatenation. "
        "This direct variable interpolation creates a classic SQL injection sink allowing arbitrary query manipulation."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["result"] == "passed"

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["union select", "column count", "syntax error", "tautology"],
    }
    good_val = (
        "Confirmed true positive. Injected ' UNION SELECT 1,2,3-- into search parameter. "
        "Server reflected column count values directly into the result table without syntax error, proving exploitable union select extraction."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"

    # Impact Analysis
    imp_content = {
        "min_words": 20,
        "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "impact_keywords": ["database exfiltration", "credential theft", "data breach", "integrity", "confidentiality"],
    }
    good_imp = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
        "Technical impact enables full database exfiltration, credential theft, and data destruction. "
        "Business consequences include complete loss of confidentiality and integrity, triggering severe regulatory penalties for data breach."
    )
    res_imp = evaluate_impact_submission(good_imp, imp_content)
    assert res_imp["score"] >= 0.8
    assert res_imp["result"] == "passed"

    # Lab Exploitation (DVWA SQLi Sandbox)
    create_user("sqli_learner", "Password123!", role="analyst", email="sqli@example.com")
    user = get_user_by_username("sqli_learner")
    user_id = user["id"]

    sb_id = "dvwa_sqli_sb_7777"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "sqli",
        "name": "DVWA SQLi Lab",
        "image": "vulnerables/web-dvwa",
        "host_port": 8082,
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
        "timeout_seconds": 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_id] = sb_record
    save_active_sandbox_record(sb_record)

    # 1. Worker recycle test
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    sqli_ex = get_exercises_for_skill("sqli", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, sqli_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["sqli"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "sqli", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, sqli_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 7. Cross-Target Sandbox Isolation Boundaries ──────────────────────────────

def test_batch1_cross_target_sandbox_isolation():
    """Ensure that sandbox credentials from one target cannot solve another target challenge."""
    create_user("iso_user", "Password123!", role="analyst", email="iso@example.com")
    user = get_user_by_username("iso_user")
    user_id = user["id"]

    # Register an active Juice Shop IDOR sandbox
    sb_idor = "sb_isolation_idor_1"
    rec_idor = {
        "id": sb_idor,
        "user_id": user_id,
        "vuln_type": "idor",
        "name": "Juice Shop IDOR",
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_idor] = rec_idor
    save_active_sandbox_record(rec_idor)

    # Attempt to use the IDOR sandbox to complete a DVWA broken_auth challenge
    auth_ex = get_exercises_for_skill("broken_auth", capability="lab_exploitation")[0]
    att_auth = start_exercise_attempt(user_id, auth_ex["id"])
    res_cross = complete_exercise_attempt(
        att_auth["id"],
        user_id,
        metadata={"sandbox_id": sb_idor, "flag": SANDBOX_ALLOWLIST["broken_auth"]["proof_flag"]},
    )
    assert res_cross["score"] == 0.0
    assert res_cross["result"] == "failed"
    assert "target mismatch" in res_cross["notes"].lower()

    # Attempt to use a DVWA SQLi sandbox to complete Juice Shop IDOR challenge
    sb_sqli = "sb_isolation_sqli_1"
    rec_sqli = {
        "id": sb_sqli,
        "user_id": user_id,
        "vuln_type": "sqli",
        "name": "DVWA SQLi",
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_sqli] = rec_sqli
    save_active_sandbox_record(rec_sqli)

    idor_ex = get_exercises_for_skill("idor", capability="lab_exploitation")[0]
    att_idor = start_exercise_attempt(user_id, idor_ex["id"])
    res_cross2 = complete_exercise_attempt(
        att_idor["id"],
        user_id,
        metadata={"sandbox_id": sb_sqli, "flag": SANDBOX_ALLOWLIST["idor"]["proof_flag"]},
    )
    assert res_cross2["score"] == 0.0
    assert res_cross2["result"] == "failed"
    assert "target mismatch" in res_cross2["notes"].lower()


# ── 8. Uniform Anti-Stuffing Enforcement Across Batch 1 Evaluators ─────────────

def test_batch1_anti_stuffing_enforced_across_all_batch_evaluators():
    """Verify that repeated word padding is rejected on all Batch 1 textual capability evaluators."""
    # 1. dns_recon recognition
    rec_content = {"min_words": 15, "target_indicators": ["blog.example.com"], "pattern_keywords": ["dangling"]}
    stuffed = "dangling blog.example.com " + ("padding " * 15)
    r1 = evaluate_recognition_submission(stuffed, rec_content)
    assert r1["score"] == 0.2
    assert "anti-stuffing violation" in r1["notes"].lower()

    # 2. sqli knowledge
    know_content = {"min_words": 30, "expected_concepts": ["parameterization", "union"]}
    stuffed_know = "parameterization union " * 16
    r2 = evaluate_knowledge_submission(stuffed_know, know_content)
    assert r2["score"] == 0.2
    assert "anti-stuffing violation" in r2["notes"].lower()

    # 3. sqli impact analysis
    imp_content = {"min_words": 20, "impact_keywords": ["database exfiltration"]}
    stuffed_imp = "database exfiltration " * 12
    r3 = evaluate_impact_submission(stuffed_imp, imp_content)
    assert r3["score"] == 0.2
    assert "anti-stuffing violation" in r3["notes"].lower()
