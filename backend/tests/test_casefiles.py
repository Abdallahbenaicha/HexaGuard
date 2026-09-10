"""Test suite for E-02: Blue Team SOC Case Files Blueprint.

Verifies:
  1. Unauthorized access to /api/casefiles is rejected.
  2. Authenticated user can list all SOC incident case files with status.
  3. Single case file endpoint returns evidence logs and scenario.
  4. Invalid case ID returns 404.
  5. Accurate investigation submission achieves passing score (>= 65%) and Socratic feedback.
  6. Incomplete/incorrect submission fails passing threshold with constructive feedback.
  7. Case completion records progress in database.
"""

import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_casefiles.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_casefiles_unauthorized():
    """Anonymous client GET /api/casefiles must be rejected (401 or 302)."""
    app = create_app()
    client = app.test_client()
    res = client.get("/api/casefiles")
    assert res.status_code in (401, 302)


def test_casefiles_list():
    """Authenticated user receives all defined SOC case files."""
    app = create_app()
    client = app.test_client()

    create_user("soc_analyst_1", "Password123!", role="analyst", email="soc1@example.com")
    user = get_user_by_username("soc_analyst_1")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/casefiles")
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    cases = data.get("cases", [])
    assert len(cases) == 4

    case_ids = {c["id"] for c in cases}
    assert "case-01-brute-ssh" in case_ids
    assert "case-02-phishing-exfil" in case_ids
    assert "case-03-web-sqli-dump" in case_ids
    assert "case-04-lateral-movement" in case_ids

    for c in cases:
        assert "status" in c
        assert "mitre_id" in c
        assert "scenario_en" in c


def test_get_casefile_detail():
    """Retrieving valid case file returns scenario and evidence log array."""
    app = create_app()
    client = app.test_client()

    create_user("soc_analyst_2", "Password123!", role="analyst", email="soc2@example.com")
    user = get_user_by_username("soc_analyst_2")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/casefiles/case-01-brute-ssh")
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    case = data.get("case", {})
    assert case.get("id") == "case-01-brute-ssh"
    assert len(case.get("evidence_logs", [])) > 0
    assert any("198.51.100.42" in line for line in case["evidence_logs"])


def test_get_casefile_not_found():
    """Non-existent case ID returns 404."""
    app = create_app()
    client = app.test_client()

    create_user("soc_analyst_3", "Password123!", role="analyst", email="soc3@example.com")
    user = get_user_by_username("soc_analyst_3")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/casefiles/unknown-case-id")
    assert res.status_code == 404
    data = res.get_json()
    assert data.get("ok") is False


def test_submit_casefile_passing_investigation():
    """Accurate investigation report earns high score, passes, and saves record."""
    app = create_app()
    client = app.test_client()

    create_user("soc_investigator", "Password123!", role="analyst", email="investigator@example.com")
    user = get_user_by_username("soc_investigator")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    payload = {
        "attacker_source": "198.51.100.42",
        "compromised_target": "deploy account on bastion",
        "mitre_technique": "T1110 Brute Force Password Spraying",
        "findings_narrative": "Attacker IP 198.51.100.42 conducted brute force, compromised deploy user via SSH, then executed sudo /bin/cat /etc/shadow to exfil root password hash.",
        "containment_plan": "Block threat actor IP 198.51.100.42 on firewall, isolate host, reset deploy account credentials, and enforce MFA.",
    }

    res = client.post("/api/casefiles/case-01-brute-ssh/submit", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    assert data.get("passed") is True
    assert data.get("score") >= 80
    assert "feedback" in data

    # Verify status is reflected on subsequent GET
    list_res = client.get("/api/casefiles")
    c1 = next(c for c in list_res.get_json()["cases"] if c["id"] == "case-01-brute-ssh")
    assert c1["status"]["passed"] is True
    assert c1["status"]["score"] >= 80


def test_submit_casefile_failing_investigation():
    """Vague or incorrect investigation receives failing score and constructive feedback."""
    app = create_app()
    client = app.test_client()

    create_user("soc_novice", "Password123!", role="analyst", email="novice@example.com")
    user = get_user_by_username("soc_novice")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    payload = {
        "attacker_source": "unknown internal",
        "compromised_target": "nobody",
        "mitre_technique": "unknown",
        "findings_narrative": "I see some logs",
        "containment_plan": "reboot the server",
    }

    res = client.post("/api/casefiles/case-01-brute-ssh/submit", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    assert data.get("passed") is False
    assert data.get("score") < 65
    assert data["feedback"]["checks"]["attacker_source"]["status"] == "fail"
