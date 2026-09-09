"""Test suite for Part 6: Research Loop (Human Disagreement Dataset E3).

Acceptance Criteria:
  1. record_human_disagreement saves records to datasets/e3_human_disagreement/ground_truth.json.
  2. Updates datasets/e3_human_disagreement/metadata.json counts and timestamps.
  3. Rejects invalid disagreement_type or empty rationale.
  4. POST /api/reports/<token>/disagreement logs disagreement and returns 200.
  5. Enforces report existence, ownership (IDOR check), and authentication.
  6. GET /api/research/disagreements returns summary stats and list of records.
"""

import json
import os
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, store_report
from research_loop import (
    record_human_disagreement,
    get_human_disagreements,
    _GROUND_TRUTH_PATH,
    _METADATA_PATH,
    _DATASET_LOCK,
)


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_research_loop.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-research-loop")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_record_human_disagreement_unit():
    """Unit test: record_human_disagreement writes to ground_truth.json and updates metadata.json."""
    token = "11111111-2222-3333-4444-555555555555"
    entry = record_human_disagreement(
        report_token=token,
        vuln_type="sql_injection",
        disagreement_type="false_positive",
        scanner_id="dast_zap",
        rationale="Parameterized prepared statement verified in backend handler.",
        evidence="Observed safe integer cast",
        target="app.test.local",
        user_id=1,
    )

    assert entry["id"].startswith("e3-")
    assert entry["vuln_type"] == "sqli"  # normalized canonical type
    assert entry["disagreement_type"] == "false_positive"

    # Verify query
    data = get_human_disagreements(limit=10)
    assert data["total"] >= 1
    assert data["summary_by_type"]["false_positive"] >= 1


def test_record_human_disagreement_validation_errors():
    """Rejects invalid disagreement_type and missing rationale."""
    with pytest.raises(ValueError, match="Invalid disagreement_type"):
        record_human_disagreement(
            report_token="11111111-2222-3333-4444-555555555555",
            vuln_type="xss",
            disagreement_type="unsupported_type",
            rationale="Some reason",
        )

    with pytest.raises(ValueError, match="Rationale is required"):
        record_human_disagreement(
            report_token="11111111-2222-3333-4444-555555555555",
            vuln_type="xss",
            disagreement_type="false_positive",
            rationale="",
        )


def test_api_report_disagreement_endpoint():
    """POST /api/reports/<token>/disagreement records disagreement via HTTP."""
    app = create_app()
    client = app.test_client()

    create_user("researcher1", "Password123!", role="analyst", email="r1@example.com")
    user = get_user_by_username("researcher1")

    # Store a dummy report
    report_data = {
        "target": "example.com",
        "scan_type": "web",
        "result": {
            "target": "example.com",
            "vulnerabilities": [
                {"check": "xss", "severity": "high"},
            ],
        },
    }
    token = store_report(
        result=report_data,
        risk_score=7.5,
        original_content=None,
        user_id=user["id"],
        username="researcher1",
    )

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post(f"/api/reports/{token}/disagreement", json={
        "vuln_type": "xss",
        "disagreement_type": "false_positive",
        "scanner_id": "web_core",
        "rationale": "CSP default-src self blocks inline script execution.",
        "evidence": "Observed CSP header in response",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert "record" in data
    assert data["record"]["vuln_type"] == "xss"

    # Test GET /api/research/disagreements
    get_resp = client.get("/api/research/disagreements")
    assert get_resp.status_code == 200
    get_data = get_resp.get_json()
    assert get_data.get("ok") is True
    assert get_data.get("total", 0) >= 1


def test_api_report_disagreement_idor_protection():
    """A user cannot log disagreements for another user's report without admin rights."""
    app = create_app()
    client = app.test_client()

    create_user("owner_user", "Password123!", role="analyst", email="owner@example.com")
    create_user("attacker_user", "Password123!", role="analyst", email="attacker@example.com")
    owner = get_user_by_username("owner_user")
    attacker = get_user_by_username("attacker_user")

    token = store_report(
        result={"target": "secret.internal", "scan_type": "web"},
        risk_score=5.0,
        original_content=None,
        user_id=owner["id"],
        username="owner_user",
    )

    with client.session_transaction() as sess:
        sess["_user_id"] = str(attacker["id"])
        sess["_fresh"] = True

    resp = client.post(f"/api/reports/{token}/disagreement", json={
        "vuln_type": "xss",
        "disagreement_type": "false_positive",
        "rationale": "Illegitimate attempt",
    })
    assert resp.status_code == 403
    data = resp.get_json()
    assert data.get("ok") is False
