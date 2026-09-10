"""Test suite for HexaGuard Legendary Protocol Wave 1:
  - YesWeHack normaliser against real arkadiyt/bounty-targets-data schema
  - Intigriti normaliser against real schema
  - Federacy normaliser against real schema
  - 5-platform registration in _PLATFORM_URLS and _NORMALISERS
  - Bidirectional learning: _suggest_lessons_for_target and _build_manual_hunt_guide
  - Skill synergy in _calculate_learn_earn_score
  - GET /api/bounty/targets-by-skill/<vuln_type> endpoint
"""

import os
import time
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username
from blueprints.bounty import (
    _PLATFORM_URLS,
    _NORMALISERS,
    _normalise_yeswehack,
    _normalise_intigriti,
    _normalise_federacy,
    _suggest_lessons_for_target,
    _build_manual_hunt_guide,
    _calculate_learn_earn_score,
    _BB_CACHE,
    _BB_CACHE_LOCK,
)


@pytest.fixture(autouse=True)
def setup_env(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_bounty_legendary.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-legendary-protocol")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("ENABLE_LIVE_BOUNTY_SCANNING", "true")
    init_db()


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        create_user("hunter_one", "Password123!", role="admin", email="hunter@example.com")
        user = get_user_by_username("hunter_one")
        with c.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])
            sess["user_id"] = user["id"]
            sess["username"] = "hunter_one"
            sess["role"] = "admin"
            sess["_fresh"] = True
        yield c


def test_all_five_platforms_registered():
    """Verify all 5 bug bounty platforms are registered in URLs and normalisers."""
    expected = {"hackerone", "bugcrowd", "yeswehack", "intigriti", "federacy"}
    assert expected.issubset(set(_PLATFORM_URLS.keys()))
    assert expected.issubset(set(_NORMALISERS.keys()))


def test_yeswehack_normaliser_real_schema():
    """Verify YesWeHack normaliser parses targets.in_scope correctly from real schema."""
    real_sample = [
        {
            "id": "1001",
            "slug": "acme-corp",
            "name": "Acme Corporation",
            "bounty": True,
            "managed": True,
            "bounty_reward_min": 100,
            "bounty_reward_max": 2500,
            "targets": {
                "in_scope": [
                    {
                        "target": "https://api.acme.com",
                        "type": "api",
                        "description": "Production GraphQL API",
                    },
                    {
                        "target": "*.acme.org",
                        "type": "web-application",
                        "description": "Wildcard web targets",
                    },
                ],
                "out_of_scope": [
                    {"target": "dev.acme.com", "type": "web-application"}
                ]
            }
        }
    ]

    results = _normalise_yeswehack(real_sample)
    assert len(results) == 2

    r0 = results[0]
    assert r0["platform"] == "yeswehack"
    assert r0["program_name"] == "Acme Corporation"
    assert r0["asset"] == "https://api.acme.com"
    assert r0["asset_type"] == "API"
    assert r0["eligible_bounty"] is True
    assert r0["managed"] is True
    assert r0["max_severity"] in ("high", "critical", "medium")

    r1 = results[1]
    assert r1["asset"] == "*.acme.org"
    assert r1["asset_type"] == "WILDCARD"


def test_intigriti_normaliser_real_schema():
    """Verify Intigriti normaliser extracts endpoint and bounty rewards."""
    real_sample = [
        {
            "id": "inti-01",
            "handle": "cyber-sec",
            "company_handle": "cyber-inc",
            "name": "Cyber Inc",
            "status": "open",
            "url": "https://app.intigriti.com/programs/cyber-inc/cyber-sec/detail",
            "max_bounty": {"value": 7500, "currency": "EUR"},
            "targets": {
                "in_scope": [
                    {
                        "endpoint": "app.cyber.io",
                        "type": None,
                        "description": "Main application endpoint",
                    },
                    {
                        "endpoint": "*.internal.cyber.io",
                        "type": "wildcard",
                        "description": "Internal test staging",
                    }
                ]
            }
        }
    ]

    results = _normalise_intigriti(real_sample)
    assert len(results) == 2
    assert results[0]["platform"] == "intigriti"
    assert results[0]["program_name"] == "Cyber Inc"
    assert results[0]["asset"] == "app.cyber.io"
    assert results[0]["max_severity"] == "critical"
    assert results[0]["eligible_bounty"] is True
    assert results[1]["asset_type"] == "WILDCARD"


def test_federacy_normaliser_real_schema():
    """Verify Federacy normaliser extracts targets and reward status."""
    real_sample = [
        {
            "id": "fed-01",
            "name": "Alpha Shield",
            "url": "https://www.federacy.com/alpha-shield",
            "offers_awards": True,
            "targets": {
                "in_scope": [
                    {
                        "target": "*.alphashield.com",
                        "type": "wildcard",
                        "description": "All subdomains in scope",
                    }
                ]
            }
        }
    ]

    results = _normalise_federacy(real_sample)
    assert len(results) == 1
    assert results[0]["platform"] == "federacy"
    assert results[0]["program_name"] == "Alpha Shield"
    assert results[0]["asset"] == "*.alphashield.com"
    assert results[0]["asset_type"] == "WILDCARD"
    assert results[0]["eligible_bounty"] is True


def test_suggest_lessons_for_target():
    """Verify _suggest_lessons_for_target maps attack surface to educational lessons."""
    # 1. Target with SQL and XSS in instructions
    t1 = {
        "instruction": "Test for blind SQL injection and DOM-based cross-site scripting",
        "asset": "shop.example.com",
        "asset_type": "URL",
    }
    s1 = _suggest_lessons_for_target(t1)
    assert "sqli" in s1
    assert "xss" in s1

    # 2. API target defaults to API relevant vulnerability classes
    t2 = {
        "instruction": "",
        "asset": "https://api.example.com/v1",
        "asset_type": "API",
    }
    s2 = _suggest_lessons_for_target(t2)
    assert "broken_auth" in s2
    assert "sensitive_data_exposure" in s2

    # 3. Wildcard domain defaults
    t3 = {
        "instruction": "",
        "asset": "*.domain.com",
        "asset_type": "WILDCARD",
    }
    s3 = _suggest_lessons_for_target(t3)
    assert "security_misconfig" in s3 or "open_redirect" in s3


def test_build_manual_hunt_guide():
    """Verify _build_manual_hunt_guide constructs structured guidance."""
    target = {
        "asset": "*.targetcorp.com",
        "asset_type": "WILDCARD",
        "scan_policy": {"status": "RESTRICTED"},
        "auto_scan_ok": False,
        "program_url": "https://hackerone.com/targetcorp",
    }

    guide = _build_manual_hunt_guide(target)
    assert guide["target"] == "*.targetcorp.com"
    assert guide["asset_type"] == "WILDCARD"
    assert guide["policy_status"] == "RESTRICTED"
    assert guide["auto_scan_ok"] is False
    assert len(guide["recon_steps"]) >= 3
    assert any("Subdomain" in step["phase"] or "Passive" in step["phase"] for step in guide["recon_steps"])
    assert len(guide["testing_focus"]) >= 3
    assert len(guide["burp_tips"]) >= 2


def test_calculate_learn_earn_score_skill_synergy():
    """Verify verified skills matching the target increase the synergy score."""
    target = {
        "scan_policy": {"status": "ALLOWED"},
        "eligible_bounty": True,
        "max_severity": "critical",
        "instruction": "Seeking SQL injection and database vulnerability reports only.",
        "asset": "db-portal.example.com",
        "asset_type": "URL",
    }

    # User A: Verified in SQLi
    ledger_verified_sqli = [
        {"vuln_type": "sqli", "status": "practiced_verified"},
    ]
    # User B: Verified only in unrelated CSRF
    ledger_verified_csrf = [
        {"vuln_type": "csrf", "status": "practiced_verified"},
    ]

    score_sqli_hunter = _calculate_learn_earn_score(target, ledger_verified_sqli)
    score_csrf_hunter = _calculate_learn_earn_score(target, ledger_verified_csrf)

    assert score_sqli_hunter > score_csrf_hunter


def test_api_bounty_targets_by_skill_endpoint(client):
    """Verify GET /api/bounty/targets-by-skill/<vuln_type> returns matched targets."""
    # Seed mock cache with known data
    mock_data = [
        {
            "submission_state": "open",
            "name": "SQLi Target Program",
            "handle": "sqli-prog",
            "url": "https://hackerone.com/sqli-prog",
            "policy": "Testing allowed",
            "targets": {
                "in_scope": [
                    {
                        "asset_identifier": "sql.example.com",
                        "asset_type": "URL",
                        "max_severity": "critical",
                        "eligible_for_bounty": True,
                        "instruction": "Database and SQL parameters are in primary scope",
                    }
                ]
            }
        }
    ]

    with _BB_CACHE_LOCK:
        _BB_CACHE["hackerone"] = {"data": mock_data, "ts": time.time()}

    resp = client.get("/api/bounty/targets-by-skill/sqli")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["vuln_type"] == "sqli"
    assert data["total_matched"] >= 1
    t = data["targets"][0]
    assert "suggested_lessons" in t
    assert "manual_hunt_guide" in t
    assert "learn_earn_score" in t
