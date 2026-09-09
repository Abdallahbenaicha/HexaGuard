"""Unit and integration tests for Bug Bounty Roadmap Phases P2 & P3:
  • P2.1: Target Scan History & Differential Analysis (get_target_scan_history, GET /api/bounty/targets/history)
  • P2.2: Findings Triage Workflow (PATCH /api/reports/vulnerabilities/<id>/triage, inheritance)
  • P2.3: Ready-to-use reproduction curl PoC generator & program max severity warning flags
  • P3.1: Standalone Safe Harbor extraction & badges (_detect_safe_harbor, safe_harbor=1 filter)
  • P3.2: Legal Consent Record PDF Export with SHA-256 fingerprint (/api/reports/<token>/consent-pdf)
  • P3.3: Expected ROI / Program Prioritization scoring (_calculate_expected_roi, sort=roi)
"""

import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest

os.environ["SECURAX_TESTING"] = "1"
os.environ["ENABLE_LIVE_BOUNTY_SCANNING"] = "true"

from app import create_app
from blueprints.bounty import _calculate_expected_roi, _detect_safe_harbor
from database import (
    create_user,
    get_report,
    get_target_scan_history,
    init_db,
    store_report,
    update_vulnerability_triage,
)
from report_generator import check_severity_cap, generate_poc_curl


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("bounty_p2_p3")
    db_file = str(tmp / "test_bounty_p2_p3.db")
    os.environ["DB_PATH"] = db_file
    import database as db_mod
    if hasattr(db_mod._local, "conn"):
        del db_mod._local.conn
    db_mod.DB_PATH = db_file

    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        init_db()
        create_user("bounty_tester", "TestPass123!", role="admin")
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["user_id"] = 1
            sess["username"] = "bounty_tester"
            sess["role"] = "admin"
        yield c


# ════════════════════════════════════════════════════════════════════════════
# P2.1: Target Scan History & Differential Analysis
# ════════════════════════════════════════════════════════════════════════════

def test_target_scan_history_diff_computation(client):
    """Test get_target_scan_history calculates new, resolved, and recurrent findings correctly."""
    target_asset = "history-test.example.com"
    platform = "hackerone"

    bounty_context = {
        "asset": target_asset,
        "platform": platform,
        "program_handle": "history-corp",
        "program_name": "History Corp",
        "acknowledged": True,
    }

    # Scan 1: Vuln A (SQLi) + Vuln B (Headers)
    result_scan1 = {
        "scan_type": "web",
        "target": target_asset,
        "risk_score": 8.0,
        "bounty_context": bounty_context,
        "vulnerabilities": [
            {
                "title": "SQL Injection in /api/search",
                "severity": "critical",
                "description": "SQL injection flaw",
                "recommendation": "Use prepared statements",
            },
            {
                "title": "Missing Security Headers",
                "severity": "low",
                "description": "HSTS not set",
                "recommendation": "Set HSTS",
            },
        ],
    }
    tok1 = store_report(
        result_scan1, risk_score=8.0, original_content=None,
        user_id=1, username="bounty_tester",
    )
    assert tok1 is not None

    # Scan 2: Vuln B (Headers) + Vuln C (XSS) - Vuln A resolved
    result_scan2 = {
        "scan_type": "web",
        "target": target_asset,
        "risk_score": 6.5,
        "bounty_context": bounty_context,
        "vulnerabilities": [
            {
                "title": "Missing Security Headers",
                "severity": "low",
                "description": "HSTS not set",
                "recommendation": "Set HSTS",
            },
            {
                "title": "Reflected Cross-Site Scripting (XSS)",
                "severity": "high",
                "description": "XSS in q param",
                "recommendation": "Sanitize output",
            },
        ],
    }
    tok2 = store_report(
        result_scan2, risk_score=6.5, original_content=None,
        user_id=1, username="bounty_tester",
    )
    assert tok2 is not None

    # Retrieve history
    history = get_target_scan_history(target_asset, platform=platform)
    assert history is not None
    assert len(history["scans"]) >= 2

    diff = history["differential"]
    assert diff is not None

    # Check New findings: Vuln C
    new_titles = [f["title"] for f in diff["new_findings"]]
    assert "Reflected Cross-Site Scripting (XSS)" in new_titles

    # Check Resolved findings: Vuln A
    resolved_titles = [f["title"] for f in diff["resolved_findings"]]
    assert "SQL Injection in /api/search" in resolved_titles

    # Check Recurrent findings: Vuln B
    recurrent_titles = [f["title"] for f in diff["recurrent_findings"]]
    assert "Missing Security Headers" in recurrent_titles

    # Verify HTTP Endpoint GET /api/bounty/targets/history
    res = client.get(f"/api/bounty/targets/history?asset={target_asset}&platform={platform}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["target_asset"] == target_asset
    assert "differential" in data
    assert len(data["scans"]) >= 2


# ════════════════════════════════════════════════════════════════════════════
# P2.2: Findings Triage Workflow & Inheritance
# ════════════════════════════════════════════════════════════════════════════

def test_findings_triage_workflow(client):
    """Test updating triage status and inheritance across scans."""
    target_asset = "triage-test.example.com"
    result = {
        "scan_type": "web",
        "target": target_asset,
        "risk_score": 7.0,
        "vulnerabilities": [
            {
                "title": "IDOR in User Profile",
                "severity": "high",
                "description": "IDOR vulnerability",
                "recommendation": "Check authorization",
            }
        ],
    }
    tok = store_report(
        result, risk_score=7.0, original_content=None,
        user_id=1, username="bounty_tester",
    )
    rep = get_report(tok)
    vulns = rep["result"]["vulnerabilities"]
    assert len(vulns) == 1
    vuln_id = vulns[0].get("id")
    assert vuln_id is not None
    assert vulns[0].get("triage_status") == "New"

    # Update triage status via PATCH
    patch_res = client.patch(
        f"/api/reports/vulnerabilities/{vuln_id}/triage",
        json={"triage_status": "Reported", "triage_notes": "Submitted to Bugcrowd #9876"},
    )
    assert patch_res.status_code == 200
    patch_data = patch_res.get_json()
    assert patch_data["triage_status"] == "Reported"
    assert patch_data["triage_notes"] == "Submitted to Bugcrowd #9876"

    # Verify invalid triage status is rejected
    bad_res = client.patch(
        f"/api/reports/vulnerabilities/{vuln_id}/triage",
        json={"triage_status": "INVALID_STATUS"},
    )
    assert bad_res.status_code == 400

    # Verify persistence upon re-fetching report
    rep_updated = get_report(tok)
    v_updated = rep_updated["result"]["vulnerabilities"][0]
    assert v_updated["triage_status"] == "Reported"
    assert v_updated["triage_notes"] == "Submitted to Bugcrowd #9876"

    # Verify status inheritance on a subsequent scan of the same target
    result_subsequent = {
        "scan_type": "web",
        "target": target_asset,
        "risk_score": 7.0,
        "vulnerabilities": [
            {
                "title": "IDOR in User Profile",
                "severity": "high",
                "description": "IDOR vulnerability recurring",
                "recommendation": "Check authorization",
            }
        ],
    }
    tok_sub = store_report(
        result_subsequent, risk_score=7.0, original_content=None,
        user_id=1, username="bounty_tester",
    )
    rep_sub = get_report(tok_sub)
    v_inherited = rep_sub["result"]["vulnerabilities"][0]
    # Should inherit 'Reported' status rather than resetting to 'New'
    assert v_inherited["triage_status"] == "Reported"


# ════════════════════════════════════════════════════════════════════════════
# P2.3: Ready-to-Use Reproduction curl PoC & Program Cap Warning
# ════════════════════════════════════════════════════════════════════════════

def test_generate_poc_curl():
    """Verify ready-to-use curl PoC generation."""
    # Test GET with custom endpoint
    vuln_get = {
        "url": "https://target.com/search?q=test",
        "method": "GET",
        "proof": "<script>alert(1)</script>",
    }
    curl_get = generate_poc_curl(vuln_get, "target.com")
    assert "curl" in curl_get
    assert "https://target.com/search?q=test" in curl_get
    assert "X-Bug-Bounty-Research" in curl_get

    # Test POST with payload
    vuln_post = {
        "path": "/api/v1/auth/reset",
        "method": "POST",
        "payload": '{"email": "admin@target.com"}',
    }
    curl_post = generate_poc_curl(vuln_post, "api.target.com")
    assert "-X POST" in curl_post
    assert "api.target.com/api/v1/auth/reset" in curl_post
    assert "--data" in curl_post


def test_check_severity_cap():
    """Verify check_severity_cap flags findings that exceed max bounty tier."""
    # Vuln is CRITICAL, program max is HIGH -> Exceeds
    cap_info = check_severity_cap("critical", "high")
    assert cap_info["exceeds_program_cap"] is True
    assert "exceeds" in cap_info["program_cap_warning"].lower()

    # Vuln is MEDIUM, program max is HIGH -> Does NOT exceed
    cap_info2 = check_severity_cap("medium", "high")
    assert cap_info2["exceeds_program_cap"] is False
    assert cap_info2["program_cap_warning"] is None

    # Program has no cap -> Does NOT exceed
    cap_info3 = check_severity_cap("critical", None)
    assert cap_info3["exceeds_program_cap"] is False


# ════════════════════════════════════════════════════════════════════════════
# P3.1: Standalone Safe Harbor Extraction & Filtering
# ════════════════════════════════════════════════════════════════════════════

def test_detect_safe_harbor():
    """Verify _detect_safe_harbor accurately parses legal commitments."""
    full_harbor_prog = {
        "policy": "We provide full safe harbor. We will not pursue legal action or DMCA claims against researchers acting in good faith."
    }
    res_full = _detect_safe_harbor(full_harbor_prog)
    assert res_full["has_safe_harbor"] is True
    assert res_full["type"] in ("standard", "gold_standard")

    no_harbor_prog = {
        "policy": "Please report bugs to security@example.com."
    }
    res_none = _detect_safe_harbor(no_harbor_prog)
    assert res_none["has_safe_harbor"] is False
    assert res_none["type"] == "none"


# ════════════════════════════════════════════════════════════════════════════
# P3.2: Legal Consent Record PDF Export with SHA-256 Fingerprint
# ════════════════════════════════════════════════════════════════════════════

def test_consent_record_pdf_generation(client):
    """Verify /api/reports/<token>/consent-pdf produces a valid, tamper-evident PDF."""
    target_asset = "consent-pdf-test.com"
    bounty_context = {
        "asset": target_asset,
        "platform": "hackerone",
        "program_handle": "consent-corp",
        "program_name": "Consent Corp",
        "acknowledged": True,
        "acknowledged_at": "2026-09-07T10:00:00Z",
        "scan_policy": {"status": "ALLOWED", "confidence": 95},
    }
    report_data = {
        "scan_type": "web",
        "target": target_asset,
        "risk_score": 4.5,
        "bounty_context": bounty_context,
        "vulnerabilities": [],
    }
    bounty_meta = {
        "bounty_platform": "hackerone",
        "bounty_program_handle": "consent-corp",
        "bounty_asset": target_asset,
        "bounty_acknowledged_by": "bounty_tester",
        "bounty_acknowledged_at": "2026-09-07T10:00:00Z",
        "bounty_policy_snapshot": {"status": "ALLOWED"},
    }
    token = store_report(
        report_data, risk_score=4.5, original_content=None,
        user_id=1, username="bounty_tester", bounty_meta=bounty_meta,
    )

    # Fetch Consent PDF
    res = client.get(f"/api/reports/{token}/consent-pdf")
    assert res.status_code == 200
    assert res.headers.get("Content-Type") == "application/pdf"
    assert "attachment" in res.headers.get("Content-Disposition", "")
    assert res.data.startswith(b"%PDF-")

    # Non-bounty report should return 404
    non_bounty_tok = store_report(
        {"scan_type": "web", "target": "regular.com", "vulnerabilities": []},
        risk_score=0.0, original_content=None,
        user_id=1, username="bounty_tester",
    )
    res_no_bounty = client.get(f"/api/reports/{non_bounty_tok}/consent-pdf")
    assert res_no_bounty.status_code == 404


# ════════════════════════════════════════════════════════════════════════════
# P3.3: Expected ROI Scoring & Program Prioritization
# ════════════════════════════════════════════════════════════════════════════

def test_expected_roi_scoring():
    """Verify _calculate_expected_roi computes reasonable 0-100 scores."""
    high_roi_target = {
        "eligible_bounty": True,
        "max_severity": "critical",
        "safe_harbor": {"has_safe_harbor": True, "type": "standard"},
        "scan_policy": {"status": "ALLOWED"},
        "avg_response_h": 12,
        "asset": "*.high-roi.com",
    }
    score_high = _calculate_expected_roi(high_roi_target)
    assert score_high >= 75

    low_roi_target = {
        "eligible_bounty": False,
        "max_severity": "low",
        "safe_harbor": {"has_safe_harbor": False, "type": "none"},
        "scan_policy": {"status": "RESTRICTED"},
        "avg_response_h": 500,
        "asset": "low-roi.com",
    }
    score_low = _calculate_expected_roi(low_roi_target)
    assert score_low < 40
