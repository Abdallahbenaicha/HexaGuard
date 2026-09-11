"""Security test suite for Shadow Manual Task IDOR & Dual-Layer Ownership (SEC-05).

Verifies that:
1. A user cannot complete another user's shadow manual task via API.
2. A user cannot complete a task from another user's report.
3. complete_shadow_task requires task-level ownership.
4. complete_shadow_task requires report-level ownership.
"""

import pytest
from database import (
    init_db,
    create_user,
    get_user_by_username,
    store_report,
    get_shadow_tasks_for_report,
    complete_shadow_task,
    get_user_skill_ledger,
)
from app import create_app


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_shadow_idor.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-idor-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def _create_user_and_report(username: str, email: str, vuln_types: list[str]) -> tuple[dict, str]:
    create_user(username, "Password123!", role="analyst", email=email)
    user = get_user_by_username(username)
    mock_scan = {
        "scan_type": "dast",
        "target": "https://test.local",
        "vulnerabilities": [
            {"check": vt, "title": f"Test {vt}", "severity": "high"} for vt in vuln_types
        ],
    }
    token = store_report(
        result=mock_scan,
        risk_score=8.0,
        original_content=None,
        user_id=user["id"],
        username=username,
    )
    return user, token


def test_user_cannot_complete_other_user_shadow_task():
    """API endpoint rejects attempts by User B to complete User A's shadow task (HTTP 403)."""
    user_a, token_a = _create_user_and_report("victim_user", "victim@test.local", ["xss", "sqli"])
    user_b, _ = _create_user_and_report("attacker_user", "attacker@test.local", ["rce"])

    app = create_app()
    client = app.test_client()

    # Authenticate as User B (attacker)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_b["id"])
        sess["_fresh"] = True

    # Attempt to complete User A's XSS task
    resp = client.post(
        f"/api/reports/{token_a}/shadow/xss/complete",
        json={"notes": "Unauthorized completion attempt"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False

    # Verify task in DB remains 'pending'
    tasks = get_shadow_tasks_for_report(token_a)
    xss_task = next(t for t in tasks if t["vuln_type"] == "xss")
    assert xss_task["status"] == "pending"


def test_user_cannot_complete_task_from_other_user_report():
    """Completing another user's task does not update the caller's Skill Ledger."""
    user_a, token_a = _create_user_and_report("owner_user", "owner@test.local", ["ssrf"])
    user_b, _ = _create_user_and_report("intruder_user", "intruder@test.local", ["idor"])

    app = create_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_b["id"])
        sess["_fresh"] = True

    resp = client.post(
        f"/api/reports/{token_a}/shadow/ssrf/complete",
        json={"notes": "Intruder notes"},
    )
    assert resp.status_code == 403

    # Ensure User B's skill ledger has NOT recorded ssrf
    ledger_b = get_user_skill_ledger(user_b["id"])
    ssrf_entry = next((item for item in ledger_b if item["vuln_type"] == "ssrf"), None)
    assert ssrf_entry is None or ssrf_entry["status"] == "theory_only"


def test_shadow_completion_requires_task_ownership():
    """complete_shadow_task() returns None when user_id does not match task ownership."""
    user_a, token_a = _create_user_and_report("task_owner", "task_owner@test.local", ["sqli"])
    user_b, _ = _create_user_and_report("other_user", "other_user@test.local", [])

    # Calling complete_shadow_task directly with user_b on user_a's report/task
    res = complete_shadow_task(
        report_token=token_a,
        vuln_type="sqli",
        user_id=user_b["id"],
        notes="Attempting direct bypass",
    )
    assert res is None

    # Verify task is still pending
    tasks = get_shadow_tasks_for_report(token_a)
    sqli_task = next(t for t in tasks if t["vuln_type"] == "sqli")
    assert sqli_task["status"] == "pending"


def test_shadow_completion_requires_report_ownership():
    """complete_shadow_task() returns None when user_id does not own the report."""
    user_a, token_a = _create_user_and_report("report_owner", "rep_owner@test.local", ["xss"])
    non_existent_user_id = 99999

    res = complete_shadow_task(
        report_token=token_a,
        vuln_type="xss",
        user_id=non_existent_user_id,
        notes="Non-existent user attempt",
    )
    assert res is None

    tasks = get_shadow_tasks_for_report(token_a)
    xss_task = next(t for t in tasks if t["vuln_type"] == "xss")
    assert xss_task["status"] == "pending"
