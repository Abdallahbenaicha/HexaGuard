"""Test suite for Part 0: Skill Ledger and Unified Vulnerability Taxonomy.

Verifies:
  1. All 15 dataset vuln_types from ground_truth.json exist in vuln_taxonomy.py.
  2. All 11 scanner engines are covered.
  3. Default ledger status is 'theory_only' showing learning gaps.
  4. Public POST attempting to write 'practiced_verified' is strictly rejected (403).
  5. Internal record_skill_progress allows 'practiced_verified' and prevents downgrade.
"""

import json
import pytest
from flask import Flask

from vuln_taxonomy import VULN_TAXONOMY, DATASET_VULN_TYPES, SCANNERS, normalize_check_to_vuln_type
from database import init_db, get_user_skill_ledger, record_skill_progress, create_user, get_user_by_username


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_securax.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_taxonomy_covers_all_ground_truth_dataset_types():
    """All 15 vuln_types in datasets/*/ground_truth.json must exist in VULN_TAXONOMY."""
    missing = DATASET_VULN_TYPES - set(VULN_TAXONOMY.keys())
    assert not missing, f"Missing ground truth dataset types: {missing}"
    assert len(VULN_TAXONOMY) >= 15


def test_all_eleven_scanners_represented():
    """All 11 scanners must be defined and mapped to taxonomy entries."""
    assert len(SCANNERS) == 11
    scanner_ids = {s["id"] for s in SCANNERS}
    mapped_scanners = {meta["scanner"] for meta in VULN_TAXONOMY.values()}
    assert scanner_ids == mapped_scanners, f"Discrepancy: {scanner_ids.symmetric_difference(mapped_scanners)}"


def test_normalization_engine():
    """Normalization should map various check IDs and titles to canonical taxonomy types."""
    # Exact check mappings
    assert normalize_check_to_vuln_type("missing_hsts") == "missing_security_headers"
    assert normalize_check_to_vuln_type("dep_vuln") == "vulnerable_dependency"
    assert normalize_check_to_vuln_type("sslyze-heartbleed") == "heartbleed_robot"
    assert normalize_check_to_vuln_type("open_port") == "open_ports"

    # SAST Bandit checks
    assert normalize_check_to_vuln_type("bandit_B301") == "deserialization"
    assert normalize_check_to_vuln_type("bandit_B602") == "rce"
    assert normalize_check_to_vuln_type("bandit_B105") == "hardcoded_secrets"

    # Title-based fallback
    assert normalize_check_to_vuln_type("unknown_check", title="Reflected Cross-Site Scripting found") == "xss"
    assert normalize_check_to_vuln_type("unknown_check", title="SQL Injection in login form") == "sqli"
    assert normalize_check_to_vuln_type("unknown_check", title="Privileged container detected", scanner="docker") == "privileged_containers"


def test_skill_ledger_defaults_to_theory_only(setup_db):
    """A fresh user should see all canonical categories defaulted to 'theory_only'."""
    create_user("testlearner", "Password123!", role="analyst", email="learner@example.com")
    user = get_user_by_username("testlearner")
    user_id = user["id"]
    ledger = get_user_skill_ledger(user_id)

    assert len(ledger) == len(VULN_TAXONOMY)
    statuses = {item["status"] for item in ledger}
    assert statuses == {"theory_only"}


def test_internal_record_progress_and_no_downgrade(setup_db):
    """Internal function can record verified progress, which cannot be downgraded by self-report."""
    create_user("verified_user", "Password123!", role="analyst", email="verified@example.com")
    user = get_user_by_username("verified_user")
    user_id = user["id"]

    # Step 1: Self-report XSS
    res1 = record_skill_progress(user_id, "xss", "practiced_self_reported", evidence_ref="lab-01")
    assert res1["status"] == "practiced_self_reported"
    assert res1["attempts_count"] == 1

    # Step 2: Verified completion
    res2 = record_skill_progress(user_id, "xss", "practiced_verified", evidence_ref="sandbox_flag_verified")
    assert res2["status"] == "practiced_verified"
    assert res2["attempts_count"] == 2

    # Step 3: Attempting to downgrade back to self-reported must retain 'practiced_verified'
    res3 = record_skill_progress(user_id, "xss", "practiced_self_reported", evidence_ref="read_guide_again")
    assert res3["status"] == "practiced_verified"
    assert res3["attempts_count"] == 3


def test_public_verified_forbidden(setup_db):
    """Public API MUST reject attempts to set 'practiced_verified' directly."""
    from app import create_app

    app = create_app()
    client = app.test_client()

    # Create & login user
    create_user("hacker_pupil", "Password123!", role="analyst", email="pupil@example.com")
    user = get_user_by_username("hacker_pupil")
    user_id = user["id"]
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    # 1. Attempt to cheat by requesting 'practiced_verified' on public route
    resp = client.post(
        "/api/skill/self-report",
        json={"vuln_type": "sqli", "status": "practiced_verified", "notes": "trying to bypass"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["code"] == "VERIFICATION_BYPASS_FORBIDDEN"

    # 2. Legitimate self-report works
    resp_ok = client.post(
        "/api/skill/self-report",
        json={"vuln_type": "sqli", "notes": "read cheat sheet"},
    )
    assert resp_ok.status_code == 200
    data_ok = resp_ok.get_json()
    assert data_ok["ok"] is True
    assert data_ok["entry"]["status"] == "practiced_self_reported"

    # 3. Verify ledger via API
    resp_ledger = client.get("/api/skill/ledger")
    assert resp_ledger.status_code == 200
    ledger_data = resp_ledger.get_json()
    sqli_item = next(item for item in ledger_data["ledger"] if item["vuln_type"] == "sqli")
    assert sqli_item["status"] == "practiced_self_reported"
