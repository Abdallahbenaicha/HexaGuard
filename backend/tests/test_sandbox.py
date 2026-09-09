"""Test suite for Part 1: Adversarial Twin Sandbox (Local Isolated Training Environments).

Acceptance Criteria:
  1. DEPLOYMENT_MODE != 'local' returns 404 (same strict gate as T-01).
  2. Max 2 active sandboxes per user (3rd is rejected with 429).
  3. Reject arbitrary user images (only allowlisted fixed images).
  4. Invalid flag returns 400 and does NOT update Skill Ledger.
  5. Valid flag updates Skill Ledger to 'practiced_verified' and terminates sandbox.
  6. Auto-cleanup timer terminates sandbox upon TTL expiration.
"""

import os
import time
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, get_user_skill_ledger
from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK, SANDBOX_ALLOWLIST


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_sandbox_suite.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES.clear()


def test_sandbox_gate_rejects_cloud_deployment(monkeypatch):
    """When DEPLOYMENT_MODE != 'local', all sandbox endpoints return 404."""
    monkeypatch.setenv("DEPLOYMENT_MODE", "cloud")
    app = create_app()
    client = app.test_client()

    create_user("cadet1", "Password123!", role="analyst", email="c1@example.com")
    user = get_user_by_username("cadet1")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    assert resp.status_code == 404
    data = resp.get_json()
    assert "restricted to local deployment mode only" in data.get("error", "")


def test_sandbox_rejects_unallowlisted_types():
    """Attempting to launch an unsupported or arbitrary image is rejected."""
    app = create_app()
    client = app.test_client()

    create_user("cadet2", "Password123!", role="analyst", email="c2@example.com")
    user = get_user_by_username("cadet2")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Unknown vuln_type
    resp = client.post("/api/sandbox/launch", json={"vuln_type": "malicious_custom_rootkit"})
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "SANDBOX_VULN_TYPE_NOT_ALLOWED"


def test_sandbox_concurrency_limit():
    """Max 2 active sandboxes per user; 3rd request is blocked with 429."""
    app = create_app()
    client = app.test_client()

    create_user("cadet3", "Password123!", role="analyst", email="c3@example.com")
    user = get_user_by_username("cadet3")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Launch 1st container
    r1 = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    assert r1.status_code == 201

    # Launch 2nd container
    r2 = client.post("/api/sandbox/launch", json={"vuln_type": "sqli"})
    assert r2.status_code == 201

    # Launch 3rd container -> must be rejected
    r3 = client.post("/api/sandbox/launch", json={"vuln_type": "rce"})
    assert r3.status_code == 429
    assert r3.get_json()["code"] == "MAX_SANDBOX_CONCURRENCY_EXCEEDED"


def test_flag_verification_updates_skill_ledger():
    """Submitting the correct flag verifies challenge and promotes Skill Ledger to practiced_verified."""
    app = create_app()
    client = app.test_client()

    create_user("cadet4", "Password123!", role="analyst", email="c4@example.com")
    user = get_user_by_username("cadet4")
    user_id = user["id"]

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    # Launch XSS challenge
    launch_res = client.post("/api/sandbox/launch", json={"vuln_type": "xss"})
    assert launch_res.status_code == 201
    sb_id = launch_res.get_json()["sandbox"]["id"]

    # 1. Submit bogus flag
    bad_res = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": "FLAG{wrong_guess}"})
    assert bad_res.status_code == 400
    assert bad_res.get_json()["code"] == "INVALID_SANDBOX_PROOF"

    # Verify skill ledger is NOT upgraded
    ledger_before = get_user_skill_ledger(user_id)
    xss_item = next(i for i in ledger_before if i["vuln_type"] == "xss")
    assert xss_item["status"] == "theory_only"

    # 2. Submit valid flag
    expected_flag = SANDBOX_ALLOWLIST["xss"]["proof_flag"]
    good_res = client.post(f"/api/sandbox/{sb_id}/complete", json={"flag": expected_flag})
    assert good_res.status_code == 200
    assert good_res.get_json()["verified"] is True

    # Verify skill ledger is NOW upgraded to practiced_verified!
    ledger_after = get_user_skill_ledger(user_id)
    xss_item_after = next(i for i in ledger_after if i["vuln_type"] == "xss")
    assert xss_item_after["status"] == "practiced_verified"
    assert xss_item_after["attempts_count"] == 1


def test_auto_cleanup_timeout(monkeypatch):
    """Sandbox terminates automatically after TTL expiration."""
    # Set a tiny timeout for testing: 1 second
    monkeypatch.setenv("SANDBOX_TEST_TIMEOUT", "1")
    app = create_app()
    client = app.test_client()

    create_user("cadet5", "Password123!", role="analyst", email="c5@example.com")
    user = get_user_by_username("cadet5")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    launch_res = client.post("/api/sandbox/launch", json={"vuln_type": "rce"})
    assert launch_res.status_code == 201
    sb_id = launch_res.get_json()["sandbox"]["id"]

    # Sleep 1.5 seconds to let timer fire
    time.sleep(1.5)

    with _SANDBOX_LOCK:
        assert _ACTIVE_SANDBOXES[sb_id]["status"] == "terminated"
