"""Test suite for Part 2: Shadow Manual Pass (Automated scan generates pending manual tasks).

Acceptance Criteria:
  1. A mock scan report with findings across 3 distinct vulnerability categories generates
     EXACTLY 3 pending shadow_manual_tasks, with zero duplicates even if multiple findings
     share the same category.
  2. All 11 scanners have explicit mappings to canonical vuln_type.
  3. GET /api/reports/<token>/shadow returns the exact pending tasks.
  4. GET /api/dashboard/shadow-backlog returns all pending tasks oldest first.
  5. Completing a shadow task marks it completed_self_reported and records
     practiced_self_reported in the Skill Ledger.
"""

import json
import pytest

from vuln_taxonomy import VULN_TAXONOMY, SCANNERS, normalize_check_to_vuln_type
from database import (
    init_db,
    create_user,
    get_user_by_username,
    store_report,
    get_shadow_tasks_for_report,
    get_user_shadow_backlog,
    complete_shadow_task,
    get_user_skill_ledger,
)


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_shadow.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_store_report_generates_exact_shadow_tasks():
    """A scan report with findings in 3 categories must produce exactly 3 pending shadow tasks."""
    create_user("shadow_hunter", "Password123!", role="analyst", email="hunter@example.com")
    user = get_user_by_username("shadow_hunter")
    user_id = user["id"]

    # Mock scan result with 5 findings across 3 unique categories:
    # 2 xss findings, 2 sqli findings, 1 open_redirect finding
    mock_scan = {
        "scan_type": "dast",
        "target": "https://vulnerable-test.local",
        "vulnerabilities": [
            {"check": "xss_reflected", "title": "Reflected XSS in search", "severity": "medium"},
            {"check": "xss_stored", "title": "Stored XSS in comment", "severity": "high"},
            {"check": "sqli_error", "title": "SQL Injection in id parameter", "severity": "high"},
            {"check": "sqli_blind", "title": "Time-based blind SQLi", "severity": "critical"},
            {"check": "open_redirect", "title": "Open URL redirection in return_to", "severity": "medium"},
        ],
    }

    report_token = store_report(
        result=mock_scan,
        risk_score=7.8,
        original_content=None,
        user_id=user_id,
        username="shadow_hunter",
    )
    assert report_token is not None

    # Retrieve generated shadow tasks
    tasks = get_shadow_tasks_for_report(report_token)

    # Must be EXACTLY 3 tasks (no duplicates for duplicate categories)
    assert len(tasks) == 3, f"Expected exactly 3 tasks, got {len(tasks)}"

    task_vuln_types = {t["vuln_type"] for t in tasks}
    assert task_vuln_types == {"xss", "sqli", "open_redirect"}

    # All must start as 'pending'
    for t in tasks:
        assert t["status"] == "pending"
        assert t["report_token"] == report_token


def test_all_11_scanners_have_explicit_normalization():
    """Checks that every scanner engine has defined tests that map to canonical types, never 'unknown'."""
    scanner_samples = [
        ("web",        "headers", "missing_security_headers"),
        ("dast",       "xss", "xss"),
        ("sast",       "bandit_B301", "deserialization"),
        ("network",    "open_port", "open_ports"),
        ("ssl",        "sslyze-heartbleed", "heartbleed_robot"),
        ("deps",       "dep_vuln", "vulnerable_dependency"),
        ("server",     "missing_hsts", "missing_security_headers"),
        ("server_ext", "missing_csp", "missing_csp"),
        ("docker",     "unknown", "privileged_containers", "Privileged container detected"),
        ("dns",        "unknown", "missing_spf_dkim_dmarc", "Missing SPF record on domain"),
        ("wordpress",  "unknown", "outdated_plugins", "Vulnerable WordPress plugin detected"),
    ]

    for item in scanner_samples:
        scanner = item[0]
        check = item[1]
        expected_type = item[2]
        title = item[3] if len(item) > 3 else ""
        resolved = normalize_check_to_vuln_type(check, title=title, scanner=scanner)
        assert resolved == expected_type, f"Scanner {scanner} check {check} resolved to {resolved}, expected {expected_type}"
        assert resolved in VULN_TAXONOMY, f"Resolved {resolved} not in canonical taxonomy"


def test_shadow_api_endpoints_and_completion_flow():
    """Tests the full API flow: retrieval, backlog, and completing a task updating Skill Ledger."""
    from app import create_app

    app = create_app()
    client = app.test_client()

    # Create & authenticate user
    create_user("cadet_hunter", "Password123!", role="analyst", email="cadet@example.com")
    user = get_user_by_username("cadet_hunter")
    user_id = user["id"]

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    # 1. Store a report with 2 findings: RCE and SSRF
    mock_scan = {
        "scan_type": "dast",
        "target": "https://staging.lab",
        "vulnerabilities": [
            {"check": "rce_exec", "title": "Remote code execution in ping utility", "severity": "critical"},
            {"check": "ssrf_internal", "title": "Server side request forgery to metadata", "severity": "high"},
        ],
    }
    report_token = store_report(
        result=mock_scan,
        risk_score=9.5,
        original_content=None,
        user_id=user_id,
        username="cadet_hunter",
    )

    # 2. GET /api/reports/<token>/shadow
    resp = client.get(f"/api/reports/{report_token}/shadow")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert len(data["tasks"]) == 2
    task_types = {t["vuln_type"] for t in data["tasks"]}
    assert task_types == {"rce", "ssrf"}

    # 3. GET /api/dashboard/shadow-backlog
    resp_backlog = client.get("/api/dashboard/shadow-backlog")
    assert resp_backlog.status_code == 200
    b_data = resp_backlog.get_json()
    assert b_data["ok"] is True
    assert b_data["count"] == 2

    # 4. Complete one task: RCE
    resp_comp = client.post(
        f"/api/reports/{report_token}/shadow/rce/complete",
        json={"notes": "Reproduced command injection manually via curl and verified safe escaping."},
    )
    assert resp_comp.status_code == 200
    comp_data = resp_comp.get_json()
    assert comp_data["ok"] is True
    assert comp_data["task"]["status"] == "completed_self_reported"

    # 5. Check backlog now has 1 remaining pending task (SSRF)
    resp_backlog2 = client.get("/api/dashboard/shadow-backlog")
    assert resp_backlog2.get_json()["count"] == 1
    assert resp_backlog2.get_json()["backlog"][0]["vuln_type"] == "ssrf"

    # 6. Verify Skill Ledger has been updated with 'practiced_self_reported' for RCE
    ledger = get_user_skill_ledger(user_id)
    rce_entry = next(item for item in ledger if item["vuln_type"] == "rce")
    assert rce_entry["status"] == "practiced_self_reported"
    assert rce_entry["attempts_count"] >= 1
    assert f"shadow_report:{report_token}" in rce_entry["evidence_ref"]
