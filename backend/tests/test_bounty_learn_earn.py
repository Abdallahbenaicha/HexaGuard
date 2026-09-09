"""Test suite for Part 4: Learn+Earn Composite Ranking in Bug Bounty Radar.

Acceptance Criteria:
  1. _calculate_learn_earn_score prioritizes allowed automated scanning over restricted/unknown.
  2. _calculate_learn_earn_score scales with bounty eligibility and severity tier.
  3. _calculate_learn_earn_score incorporates user skill ledger gaps (higher score for targets matching unverified skills).
  4. GET /api/admin/bounty-targets?sort=learn_earn returns targets sorted descending by learn_earn_score.
  5. Preserves T-01 local-only gate (404 when DEPLOYMENT_MODE != 'local').
"""

import os
import time
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, record_skill_progress
from blueprints.bounty import _calculate_learn_earn_score, _BB_CACHE, _BB_CACHE_LOCK


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_bounty_learn_earn.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-bounty-learn-earn")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("ENABLE_LIVE_BOUNTY_SCANNING", "true")
    init_db()


def test_learn_earn_score_policy_weighting():
    """ALLOWED policy should yield significantly higher score than RESTRICTED."""
    allowed_target = {
        "scan_policy": {"status": "ALLOWED"},
        "eligible_bounty": True,
        "max_severity": "critical",
        "instruction": "Automated scanning allowed on web app",
    }
    restricted_target = {
        "scan_policy": {"status": "RESTRICTED"},
        "eligible_bounty": True,
        "max_severity": "critical",
        "instruction": "Strictly manual testing only, no automated scanners",
    }

    score_allowed = _calculate_learn_earn_score(allowed_target)
    score_restricted = _calculate_learn_earn_score(restricted_target)

    assert score_allowed > score_restricted * 3
    assert score_allowed > 0


def test_learn_earn_score_payout_weighting():
    """Critical + bounty target should score higher than low + no bounty target."""
    high_target = {
        "scan_policy": {"status": "ALLOWED"},
        "eligible_bounty": True,
        "max_severity": "critical",
    }
    low_target = {
        "scan_policy": {"status": "ALLOWED"},
        "eligible_bounty": False,
        "max_severity": "low",
    }

    score_high = _calculate_learn_earn_score(high_target)
    score_low = _calculate_learn_earn_score(low_target)

    assert score_high > score_low


def test_learn_earn_score_responds_to_user_skill_gaps():
    """Targets mentioning skills that the user has NOT verified should receive a bonus."""
    target = {
        "scan_policy": {"status": "ALLOWED"},
        "eligible_bounty": True,
        "max_severity": "high",
        "instruction": "Test authentication workflows, SQL injection parameters, and cross-site scripting vulnerabilities.",
        "program_name": "Acme Auth Portal",
        "asset": "auth.acme.com",
    }

    # Scenario A: User has gaps in sqli, xss, broken_auth
    ledger_with_gaps = [
        {"vuln_type": "sqli", "status": "theory_only"},
        {"vuln_type": "xss", "status": "theory_only"},
        {"vuln_type": "broken_auth", "status": "theory_only"},
        {"vuln_type": "csrf", "status": "practiced_verified"},
    ]

    # Scenario B: User has mastered all those skills
    ledger_mastered = [
        {"vuln_type": "sqli", "status": "practiced_verified"},
        {"vuln_type": "xss", "status": "practiced_verified"},
        {"vuln_type": "broken_auth", "status": "practiced_verified"},
        {"vuln_type": "csrf", "status": "practiced_verified"},
    ]

    score_with_gaps = _calculate_learn_earn_score(target, ledger_with_gaps)
    score_mastered = _calculate_learn_earn_score(target, ledger_mastered)

    # User with matching skill gaps gets higher learning priority score
    assert score_with_gaps > score_mastered


def test_api_bounty_targets_sort_learn_earn(monkeypatch):
    """GET /api/admin/bounty-targets?sort=learn_earn sorts targets descending by learn_earn_score."""
    app = create_app()
    client = app.test_client()

    create_user("admin_le", "Password123!", role="admin", email="admin_le@example.com")
    user = get_user_by_username("admin_le")

    # Populate mock cache with known targets
    mock_h1_data = [
        {
            "submission_state": "open",
            "name": "Target Alpha",
            "handle": "alpha",
            "url": "https://hackerone.com/alpha",
            "policy": "Automated scanning allowed",
            "targets": {
                "in_scope": [
                    {
                        "asset_identifier": "alpha.example.com",
                        "asset_type": "URL",
                        "max_severity": "critical",
                        "eligible_for_bounty": True,
                        "instruction": "Automated tools allowed",
                    },
                    {
                        "asset_identifier": "beta.example.com",
                        "asset_type": "URL",
                        "max_severity": "low",
                        "eligible_for_bounty": False,
                        "instruction": "Manual testing only",
                    },
                ]
            },
        }
    ]

    with _BB_CACHE_LOCK:
        _BB_CACHE["hackerone"] = {"data": mock_h1_data, "ts": time.time()}

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.get("/api/admin/bounty-targets?platform=hackerone&policy=ALL&sort=learn_earn")
    assert resp.status_code == 200
    data = resp.get_json()
    targets = data.get("targets", [])
    assert len(targets) == 2

    # Verify each target has learn_earn_score
    for t in targets:
        assert "learn_earn_score" in t
        assert isinstance(t["learn_earn_score"], (int, float))

    # Verify descending sort order
    scores = [t["learn_earn_score"] for t in targets]
    assert scores == sorted(scores, reverse=True)
    assert targets[0]["asset"] == "alpha.example.com"


def test_bounty_learn_earn_preserves_local_gate(monkeypatch):
    """When DEPLOYMENT_MODE != 'local', /api/admin/bounty-targets returns 404."""
    monkeypatch.setenv("DEPLOYMENT_MODE", "cloud")
    app = create_app()
    client = app.test_client()

    create_user("cloud_admin", "Password123!", role="admin", email="ca@example.com")
    user = get_user_by_username("cloud_admin")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.get("/api/admin/bounty-targets?sort=learn_earn")
    assert resp.status_code == 404
