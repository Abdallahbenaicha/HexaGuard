"""Phase 2B Batch 2 Test Suite: Final 5 Foundational Skills Implementation.

Covers:
  1. ssrf (Juice Shop Sandbox): recognition, validation, lab_exploitation, worker-recycle, cold-reboot/fail-closed.
  2. path_traversal (DVWA Sandbox): recognition, validation, lab_exploitation, worker-recycle, cold-reboot/fail-closed.
  3. file_upload (DVWA Sandbox): recognition, validation, lab_exploitation, worker-recycle, cold-reboot/fail-closed.
  4. cve_cvss_epss: knowledge, recognition, impact_analysis (CVSS + EPSS composite risk).
  5. bug_bounty_reporting: recognition, reporting (4 mandatory sections), remediation (VDP / RFC 9116).
  6. Cross-target sandbox isolation boundaries (SSRF vs Path Traversal vs File Upload).
  7. Uniform anti-stuffing enforcement across all Batch 2 textual evaluators.
"""

from __future__ import annotations

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
    evaluate_validation_submission,
    evaluate_impact_submission,
    evaluate_remediation_submission,
    evaluate_reporting_submission,
)
from seed_learning import seed


@pytest.fixture(autouse=True)
def setup_batch2_environment(tmp_path, monkeypatch):
    """Isolate test database and active sandbox registry for each test."""
    test_db = str(tmp_path / "test_batch2.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-batch2-secret")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    # Seed all curriculum exercises
    seed()


# ── 1. Seeding Integrity for Batch 2 ──────────────────────────────────────────

def test_batch2_exercises_seeded_successfully():
    """Verify that all 5 Batch 2 skills have their required exercises properly seeded."""
    ssrf_ex = get_exercises_for_skill("ssrf")
    pt_ex = get_exercises_for_skill("path_traversal")
    upload_ex = get_exercises_for_skill("file_upload")
    cve_ex = get_exercises_for_skill("cve_cvss_epss")
    bb_ex = get_exercises_for_skill("bug_bounty_reporting")

    assert len(ssrf_ex) >= 3
    assert len(pt_ex) >= 3
    assert len(upload_ex) >= 3
    assert len(cve_ex) >= 3
    assert len(bb_ex) >= 3

    # Verify capabilities present
    assert {e["capability"] for e in ssrf_ex} >= {"recognition", "validation", "lab_exploitation"}
    assert {e["capability"] for e in pt_ex} >= {"recognition", "validation", "lab_exploitation"}
    assert {e["capability"] for e in upload_ex} >= {"recognition", "validation", "lab_exploitation"}
    assert {e["capability"] for e in cve_ex} >= {"knowledge", "impact_analysis", "reporting"}
    assert {e["capability"] for e in bb_ex} >= {"reporting", "impact_analysis", "remediation"}


# ── 2. Skill 1: ssrf Evaluators & Juice Shop Sandbox ─────────────────────────

def test_ssrf_evaluators_and_juiceshop_sandbox():
    """Validates ssrf recognition, validation, and Juice Shop sandbox with worker recycle & cold-reboot."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["requests.get(avatar_url)", "169.254.169.254", "/api/import-avatar", "line 11"],
        "pattern_keywords": ["unvalidated url", "metadata", "loopback", "internal service", "ssrf sink"],
    }
    good_rec = (
        "In route /api/import-avatar at line 11, requests.get(avatar_url) directly fetches an unvalidated url "
        "without loopback or metadata range filtering. This creates an ssrf sink allowing attackers to coerce requests "
        "to internal service interfaces and cloud metadata at 169.254.169.254."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["score"] <= 0.9
    assert res_rec["result"] == "passed"
    assert res_rec["is_verified"] == 0

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["metadata extracted", "iam credentials", "out-of-band", "internal network"],
    }
    good_val = (
        "Confirmed true positive. The SSRF payload successfully triggered an out-of-band callback and extracted AWS "
        "metadata extracted containing temporary IAM credentials from the internal network loopback interface."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"
    assert res_val["is_verified"] == 0

    # Lab Exploitation (Juice Shop SSRF Sandbox)
    create_user("ssrf_learner", "Password123!", role="analyst", email="ssrf@example.com")
    user = get_user_by_username("ssrf_learner")
    user_id = user["id"]

    sb_id = "juice_ssrf_sb_1001"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "ssrf",
        "name": "Juice Shop SSRF Challenge",
        "image": "bkimminich/juice-shop",
        "host_port": 3000,
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

    ssrf_ex = get_exercises_for_skill("ssrf", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, ssrf_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["ssrf"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "ssrf", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test: Delete from DB & memory -> MUST fail-closed 404
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, ssrf_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 3. Skill 2: path_traversal Evaluators & DVWA Sandbox ──────────────────────

def test_path_traversal_evaluators_and_dvwa_sandbox():
    """Validates path_traversal recognition, validation, and DVWA sandbox with worker recycle & cold-reboot."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["os.path.join(STORAGE_DIR, filename)", "send_file(file_path)", "/download", "line 10"],
        "pattern_keywords": ["concatenation", "directory traversal", "dot-dot-slash", "unvalidated path", "filesystem sink"],
    }
    good_rec = (
        "In route /download at line 10, the call os.path.join(STORAGE_DIR, filename) performs direct path concatenation "
        "with an unvalidated path parameter before passing it to send_file(file_path). An attacker can inject dot-dot-slash "
        "sequences to trigger directory traversal and reach the underlying filesystem sink."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["score"] <= 0.9
    assert res_rec["result"] == "passed"
    assert res_rec["is_verified"] == 0

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["root:x:0:0", "passwd leaked", "arbitrary read", "traversal confirmed", "operating system file"],
    }
    good_val = (
        "Confirmed true positive. Traversal payload ../../../../etc/passwd successfully read root:x:0:0 from the underlying "
        "operating system file, proving arbitrary read and confirmed traversal with system passwd leaked."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"
    assert res_val["is_verified"] == 0

    # Lab Exploitation (DVWA Path Traversal Sandbox)
    create_user("pt_learner", "Password123!", role="analyst", email="pt@example.com")
    user = get_user_by_username("pt_learner")
    user_id = user["id"]

    sb_id = "dvwa_pt_sb_2002"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "path_traversal",
        "name": "DVWA Path Traversal Challenge",
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

    pt_ex = get_exercises_for_skill("path_traversal", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, pt_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["path_traversal"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "path_traversal", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, pt_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 4. Skill 3: file_upload Evaluators & DVWA Sandbox ─────────────────────────

def test_file_upload_evaluators_and_dvwa_sandbox():
    """Validates file_upload recognition, validation, and DVWA sandbox with worker recycle & cold-reboot."""
    # Recognition
    rec_content = {
        "min_words": 15,
        "target_indicators": ["file.save(destination)", "UPLOAD_FOLDER", "file.filename", "line 12"],
        "pattern_keywords": ["unrestricted upload", "webroot", "extension bypass", "executable directory", "webshell sink"],
    }
    good_rec = (
        "The controller at line 12 executes file.save(destination) using client-supplied file.filename directly inside "
        "UPLOAD_FOLDER located in the webroot. Without extension bypass protections, this unrestricted upload places arbitrary "
        "code into an executable directory serving as a dangerous webshell sink."
    )
    res_rec = evaluate_recognition_submission(good_rec, rec_content)
    assert res_rec["score"] >= 0.8
    assert res_rec["score"] <= 0.9
    assert res_rec["result"] == "passed"
    assert res_rec["is_verified"] == 0

    # Validation
    val_content = {
        "expected_classification": "true_positive",
        "proof_indicators": ["code execution", "rce confirmed", "php executed", "webshell proof", "script execution"],
    }
    good_val = (
        "Confirmed true positive. Dynamic script execution was verified where PHP executed the test payload and output 1764. "
        "This demonstrates full arbitrary code execution, providing webshell proof and RCE confirmed on the host."
    )
    res_val = evaluate_validation_submission(good_val, val_content)
    assert res_val["score"] >= 0.8
    assert res_val["result"] == "passed"
    assert res_val["is_verified"] == 0

    # Lab Exploitation (DVWA File Upload Sandbox)
    create_user("upload_learner", "Password123!", role="analyst", email="upload@example.com")
    user = get_user_by_username("upload_learner")
    user_id = user["id"]

    sb_id = "dvwa_upload_sb_3003"
    sb_record = {
        "id": sb_id,
        "user_id": user_id,
        "vuln_type": "file_upload",
        "name": "DVWA File Upload Lab",
        "image": "vulnerables/web-dvwa",
        "host_port": 8083,
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

    upload_ex = get_exercises_for_skill("file_upload", capability="lab_exploitation")[0]
    att1 = start_exercise_attempt(user_id, upload_ex["id"])
    correct_flag = SANDBOX_ALLOWLIST["file_upload"]["proof_flag"]

    res_lab = complete_exercise_attempt(att1["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_lab["score"] == 1.0
    assert res_lab["result"] == "passed"
    assert res_lab["evaluation_status"] == "system_verified"

    ev = get_capability_evidence(user_id, "file_upload", capability="lab_exploitation")
    assert len(ev) == 1
    assert ev[0]["is_verified"] == 1
    assert ev[0]["score"] == 1.0

    # 2. Cold reboot / Complete wipe test
    delete_active_sandbox_record(sb_id)
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()

    att2 = start_exercise_attempt(user_id, upload_ex["id"])
    res_wiped = complete_exercise_attempt(att2["id"], user_id, metadata={"sandbox_id": sb_id, "flag": correct_flag})
    assert res_wiped["score"] == 0.0
    assert res_wiped["result"] == "failed"
    assert res_wiped["attempt"]["evidence_id"] is None
    assert "not found" in res_wiped["notes"].lower()


# ── 5. Skill 4: cve_cvss_epss Evaluators ──────────────────────────────────────

def test_cve_cvss_epss_evaluators():
    """Validates cve_cvss_epss knowledge, recognition, and impact analysis evaluators."""
    # Knowledge
    know_content = {
        "min_words": 30,
        "expected_concepts": ["cvss", "epss", "probability", "severity", "cisa kev"],
    }
    good_know = (
        "Modern vulnerability prioritization separates technical severity from exploitation probability. "
        "While CVSS quantifies intrinsic technical impact, EPSS estimates the 30-day likelihood of real-world exploitation. "
        "Actively weaponized exploits cataloged in CISA KEV demand immediate triage over theoretical high CVSS flaws."
    )
    res_know = evaluate_knowledge_submission(good_know, know_content)
    assert res_know["score"] >= 0.8
    assert res_know["score"] <= 0.9
    assert res_know["result"] == "passed"
    assert res_know["is_verified"] == 0

    # Reporting (Vulnerability Intelligence Brief / Advisory)
    rep_content = {
        "min_words": 40,
        "required_sections": ["summary", "cvss", "epss", "remediation"],
    }
    good_rep = (
        "### Summary\n"
        "Critical vulnerability CVE-2021-44228 identified in log4j-core library across production services.\n\n"
        "### CVSS Metrics\n"
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H Base Score 10.0 Critical.\n\n"
        "### EPSS Probability\n"
        "EPSS score 0.975 (99th percentile) with confirmed CISA KEV active exploitation in wild.\n\n"
        "### Remediation\n"
        "Immediate emergency hotfix within 24 hours: upgrade log4j-core to 2.17.1 or higher."
    )
    res_rep = evaluate_reporting_submission(good_rep, rep_content)
    assert res_rep["score"] >= 0.8
    assert res_rep["score"] <= 0.9
    assert res_rep["result"] == "passed"
    assert res_rep["is_verified"] == 0

    # Impact Analysis
    imp_content = {
        "min_words": 20,
        "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "impact_keywords": ["composite risk", "epss probability", "cisa kev", "prioritization", "weaponization", "triage"],
    }
    good_imp = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
        "Calculating composite risk requires prioritizing known weaponization in CISA KEV alongside high EPSS probability. "
        "Our triage policy escalates actively weaponized exploits to 48-hour remediation while scheduling theoretical bugs for regular sprint cycles."
    )
    res_imp = evaluate_impact_submission(good_imp, imp_content)
    assert res_imp["score"] >= 0.8
    assert res_imp["result"] == "passed"
    assert res_imp["is_verified"] == 0


# ── 6. Skill 5: bug_bounty_reporting Evaluators ────────────────────────────────

def test_bug_bounty_reporting_evaluators():
    """Validates bug_bounty_reporting reporting (4 sections), impact analysis, and remediation evaluators."""
    # Impact Analysis (Blast radius and financial / regulatory impact justification)
    imp_content = {
        "min_words": 20,
        "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "impact_keywords": ["blast radius", "business impact", "privilege escalation", "financial risk", "bounty payout"],
    }
    good_imp = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
        "The technical blast radius enables complete privilege escalation to cluster administrative control. "
        "The resulting business impact incurs severe financial risk under GDPR data breach liabilities, justifying a Critical bounty payout tier."
    )
    res_imp = evaluate_impact_submission(good_imp, imp_content)
    assert res_imp["score"] >= 0.8
    assert res_imp["score"] <= 0.9
    assert res_imp["result"] == "passed"
    assert res_imp["is_verified"] == 0

    # Reporting (Mandatory 4 Sections: Summary, Steps to Reproduce, Impact, Remediation)
    report_content = {
        "min_words": 40,
        "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
    }
    good_report = (
        "### Summary\n"
        "Unauthenticated Remote Code Execution was discovered in the file upload endpoint.\n\n"
        "### Steps to Reproduce\n"
        "1. Send a POST request with payload avatar.php.\n"
        "2. Request the uploaded file path /uploads/avatar.php.\n"
        "3. Observe arbitrary code output confirming execution.\n\n"
        "### Impact\n"
        "Allows full compromise of backend infrastructure and confidential databases.\n\n"
        "### Remediation\n"
        "Enforce strict extension whitelisting, rename files to randomized UUIDs, and store outside webroot."
    )
    res_report = evaluate_reporting_submission(good_report, report_content)
    assert res_report["score"] >= 0.8
    assert res_report["score"] <= 0.9
    assert res_report["result"] == "passed"
    assert res_report["is_verified"] == 0

    # Remediation (VDP and RFC 9116 security.txt)
    rem_content = {
        "defense_concepts": ["security.txt", "vdp", "safe harbor", "contact", "sla", "rfc 9116"],
        "prohibited_patterns": ["unauthorized access prohibited without exception", "immediate prosecution"],
    }
    good_rem = (
        "Implemented RFC 9116 compliant security.txt hosted at /.well-known/security.txt. "
        "The published VDP formalizes legal safe harbor protections for ethical researchers, defines clear security contact channels, "
        "and commits to defined triage SLA response windows."
    )
    res_rem = evaluate_remediation_submission(good_rem, rem_content)
    assert res_rem["score"] >= 0.8
    assert res_rem["score"] <= 0.9
    assert res_rem["result"] == "passed"
    assert res_rem["is_verified"] == 0


# ── 7. Cross-Target Sandbox Isolation Boundaries ──────────────────────────────

def test_batch2_cross_target_sandbox_isolation():
    """Ensure that sandbox credentials cannot be reused across mismatched Batch 2 targets."""
    create_user("iso2_user", "Password123!", role="analyst", email="iso2@example.com")
    user = get_user_by_username("iso2_user")
    user_id = user["id"]

    # 1. Register an active Juice Shop SSRF sandbox
    sb_ssrf = "sb_iso_ssrf_1"
    rec_ssrf = {
        "id": sb_ssrf,
        "user_id": user_id,
        "vuln_type": "ssrf",
        "name": "Juice Shop SSRF",
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_ssrf] = rec_ssrf
    save_active_sandbox_record(rec_ssrf)

    # Attempt to use the SSRF sandbox to complete a DVWA Path Traversal challenge
    pt_ex = get_exercises_for_skill("path_traversal", capability="lab_exploitation")[0]
    att_pt = start_exercise_attempt(user_id, pt_ex["id"])
    res_cross1 = complete_exercise_attempt(
        att_pt["id"],
        user_id,
        metadata={"sandbox_id": sb_ssrf, "flag": SANDBOX_ALLOWLIST["path_traversal"]["proof_flag"]},
    )
    assert res_cross1["score"] == 0.0
    assert res_cross1["result"] == "failed"
    assert "target mismatch" in res_cross1["notes"].lower()

    # 2. Register an active DVWA File Upload sandbox
    sb_upload = "sb_iso_upload_1"
    rec_upload = {
        "id": sb_upload,
        "user_id": user_id,
        "vuln_type": "file_upload",
        "name": "DVWA File Upload",
        "status": "running",
        "completed": False,
        "expires_at": time.time() + 3600,
    }
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sb_upload] = rec_upload
    save_active_sandbox_record(rec_upload)

    # Attempt to use the File Upload sandbox to complete Juice Shop SSRF challenge
    ssrf_ex = get_exercises_for_skill("ssrf", capability="lab_exploitation")[0]
    att_ssrf = start_exercise_attempt(user_id, ssrf_ex["id"])
    res_cross2 = complete_exercise_attempt(
        att_ssrf["id"],
        user_id,
        metadata={"sandbox_id": sb_upload, "flag": SANDBOX_ALLOWLIST["ssrf"]["proof_flag"]},
    )
    assert res_cross2["score"] == 0.0
    assert res_cross2["result"] == "failed"
    assert "target mismatch" in res_cross2["notes"].lower()


# ── 8. Uniform Anti-Stuffing Enforcement Across Batch 2 Evaluators ─────────────

def test_batch2_anti_stuffing_enforced_across_all_batch_evaluators():
    """Verify that repeated word padding is rejected on all Batch 2 textual capability evaluators."""
    # 1. ssrf recognition
    rec_content = {"min_words": 15, "target_indicators": ["requests.get"], "pattern_keywords": ["unvalidated url"]}
    stuffed_ssrf = "unvalidated url requests.get " + ("padding " * 15)
    r1 = evaluate_recognition_submission(stuffed_ssrf, rec_content)
    assert r1["score"] == 0.2
    assert "anti-stuffing violation" in r1["notes"].lower()

    # 2. cve_cvss_epss knowledge
    know_content = {"min_words": 30, "expected_concepts": ["cvss", "epss"]}
    stuffed_cve = "cvss epss " * 16
    r2 = evaluate_knowledge_submission(stuffed_cve, know_content)
    assert r2["score"] == 0.2
    assert "anti-stuffing violation" in r2["notes"].lower()

    # 3. bug_bounty_reporting reporting
    report_content = {"min_words": 40, "required_sections": ["summary", "impact"]}
    stuffed_bb = "summary impact " * 22
    r3 = evaluate_reporting_submission(stuffed_bb, report_content)
    assert r3["score"] == 0.2
    assert "anti-stuffing violation" in r3["notes"].lower()
