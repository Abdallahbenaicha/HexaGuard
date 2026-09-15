"""Unit and integration tests for Phase 2C: Closed-Loop Remediation Engine.

Validates:
1. Authoritative Declarative Security Headers verification (is_verified = 1, score = 1.0).
2. Rejection of prohibited patterns (unsafe-inline, unsafe-eval).
3. Authoritative RFC 9116 security.txt & VDP Safe Harbor verification (is_verified = 1, score = 1.0).
4. Score capping for incomplete VDP submissions (score <= 0.9, is_verified = 0).
5. Central SSRF & target-lock enforcement for live target remediation.
6. SEC-05 Report Ownership Gate on POST /api/reports/vulnerabilities/<id>/verify-fix (IDOR rejection).
7. Successful authoritative fix verification & database state transition (is_fixed = 1, status = 'Resolved').
"""

import json
import os
import pytest

os.environ["SECURAX_TESTING"] = "1"
os.environ["DEPLOYMENT_MODE"] = "local"

from app import create_app
from database import (
    init_db,
    create_user,
    get_user_by_username,
    store_report,
    verify_and_resolve_vulnerability,
)
from db.exercise_engine import (
    evaluate_remediation_submission,
    evaluate_submission,
)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_phase2c.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-phase2c")
    init_db()


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app.test_client()


# ── 1. Declarative Security Headers Evaluator Tests ─────────────────────────────

def test_headers_remediation_authoritative_verified():
    """Exercise 16: Complete hardened reverse-proxy headers earn is_verified=1 and score=1.0."""
    content = {
        "vuln_type": "missing_security_headers",
        "defense_concepts": [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        ],
        "prohibited_patterns": ["unsafe-inline", "unsafe-eval", "http://"],
    }
    submission = """
    # Nginx Reverse Proxy Hardened Security Headers Configuration
    server {
        listen 443 ssl http2;
        server_name secure.example.com;

        # Declarative Defense Directives
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none';" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    }
    """
    res = evaluate_remediation_submission(
        submission_text=submission,
        content=content,
        vuln_type="missing_security_headers",
    )
    assert res["score"] == 1.0
    assert res["is_verified"] == 1
    assert res["result"] == "passed"
    assert res["evaluation_status"] == "system_verified"
    assert res["evidence_type"] == "VERIFIED"
    assert "verified" in res["notes"].lower()


def test_headers_remediation_prohibited_pattern_rejected():
    """Exercise 16: Inclusion of unsafe-inline fails immediately with score=0.25 and is_verified=0."""
    content = {
        "vuln_type": "missing_security_headers",
        "defense_concepts": ["content-security-policy", "x-frame-options"],
        "prohibited_patterns": ["unsafe-inline", "unsafe-eval", "http://"],
    }
    insecure_submission = """
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline';";
    add_header X-Frame-Options "DENY";
    """
    res = evaluate_remediation_submission(
        submission_text=insecure_submission,
        content=content,
        vuln_type="missing_security_headers",
    )
    assert res["score"] == 0.25
    assert res["is_verified"] == 0
    assert res["result"] == "failed"
    assert "prohibited anti-pattern" in res["notes"].lower()


# ── 2. RFC 9116 security.txt & VDP Policy Evaluator Tests ───────────────────────

def test_rfc9116_vdp_authoritative_verified():
    """Exercise 40: Complete RFC 9116 & VDP policy earns is_verified=1 and score=1.0."""
    content = {
        "vuln_type": "bug_bounty_reporting",
        "defense_concepts": ["security.txt", "vdp", "safe harbor", "contact", "sla", "rfc 9116"],
        "prohibited_patterns": ["unauthorized access prohibited without exception", "immediate prosecution"],
    }
    submission = """
    # RFC 9116 Coordinated Vulnerability Disclosure & security.txt Policy
    Contact: mailto:security@example.com
    Contact: https://example.com/security/report
    Expires: 2027-12-31T23:59:59.000Z
    Policy: https://example.com/security/vdp
    Preferred-Languages: en, ar

    # Coordinated Vulnerability Disclosure & Safe Harbor Agreement:
    We pledge that security researchers conducting testing in good faith within scope
    are granted explicit Safe Harbor. We will not pursue legal action against researchers
    who discover vulnerabilities responsibly.

    # SLA and Response Commitments:
    Our security team commits to an initial triage SLA within 48 hours and remediation SLA within 30 days.
    """
    res = evaluate_remediation_submission(
        submission_text=submission,
        content=content,
        vuln_type="bug_bounty_reporting",
    )
    assert res["score"] == 1.0
    assert res["is_verified"] == 1
    assert res["result"] == "passed"
    assert res["evaluation_status"] == "system_verified"
    assert res["evidence_type"] == "VERIFIED"


def test_rfc9116_vdp_missing_safe_harbor_capped():
    """Exercise 40: Submission lacking Safe Harbor falls back to static capping (score <= 0.9, is_verified=0)."""
    content = {
        "vuln_type": "bug_bounty_reporting",
        "defense_concepts": ["security.txt", "vdp", "contact", "sla", "rfc 9116"],
        "prohibited_patterns": ["immediate prosecution"],
    }
    incomplete_submission = """
    Contact: mailto:security@example.com
    Expires: 2027-12-31T23:59:59.000Z
    Policy: https://example.com/vdp
    We accept vulnerability reports. Response SLA is 3 days.
    """
    res = evaluate_remediation_submission(
        submission_text=incomplete_submission,
        content=content,
        vuln_type="bug_bounty_reporting",
    )
    assert res["score"] <= 0.9
    assert res["is_verified"] == 0
    assert res["evidence_type"] == "EVALUATED"


# ── 3. Central SSRF Guard Enforcement on Live Remediation ───────────────────────

def test_live_remediation_ssrf_blocked():
    """Live target remediation strictly enforces central check_ssrf guard on private/loopback IPs."""
    content = {"defense_concepts": ["firewall", "remediation"]}
    for blocked_target in ["http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data", "http://10.0.0.5"]:
        res = evaluate_remediation_submission(
            submission_text="Configured proxy to block unauthorized access.",
            content=content,
            metadata={"target_url": blocked_target},
            user_id=1,
            vuln_type="remediation",
        )
        assert res["score"] == 0.0
        assert res["is_verified"] == 0
        assert res["result"] == "failed"
        assert "ssrf" in res["notes"].lower()


# ── 4. SEC-05 Report Ownership Gate Tests on verify-fix ──────────────────────────

def test_verify_fix_endpoint_sec05_ownership(client):
    """SEC-05: User B cannot verify or resolve a vulnerability from User A's scan report."""
    create_user("user_a", "Password123!", email="a@example.com", role="analyst")
    create_user("user_b", "Password123!", email="b@example.com", role="analyst")
    user_a = get_user_by_username("user_a")
    user_b = get_user_by_username("user_b")

    # Store a scan report owned by user_a with 1 finding
    report_data = {
        "scan_type": "web",
        "target": "https://owned-by-a.example.com",
        "risk_score": 50,
        "vulnerabilities": [
            {
                "check": "missing_headers",
                "severity": "Medium",
                "title": "Missing Content-Security-Policy",
                "description": "CSP header is missing.",
                "remediation": "Configure CSP header.",
            }
        ],
    }
    report_token = store_report(report_data, 50.0, None, user_id=user_a["id"], username="user_a")

    # Retrieve vuln_id from DB
    from database import get_report
    rep = get_report(report_token)
    vuln_id = rep["result"]["vulnerabilities"][0]["id"]

    # Log in as user_b (attacker / unauthorized user)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_b["id"])
        sess["user_id"] = user_b["id"]
        sess["username"] = "user_b"
        sess["role"] = "analyst"

    # Attempt to verify fix on user_a's finding -> MUST FAIL WITH 403
    res = client.post(f"/api/reports/vulnerabilities/{vuln_id}/verify-fix")
    assert res.status_code == 403
    body = res.get_json()
    assert body["code"] == "IDOR_BLOCKED"
    assert "access denied" in body["error"].lower()


def test_verify_fix_endpoint_success(client):
    """Report owner successfully verifies fix, transitioning finding to is_fixed=1 and Resolved."""
    create_user("owner_user", "Password123!", email="owner@example.com", role="analyst")
    owner = get_user_by_username("owner_user")

    report_data = {
        "scan_type": "web",
        "target": "https://owner.example.com",
        "risk_score": 40,
        "vulnerabilities": [
            {
                "check": "x_frame_options",
                "severity": "Low",
                "title": "Missing X-Frame-Options Header",
                "description": "Clickjacking protection header is missing.",
                "remediation": "Add X-Frame-Options DENY.",
            }
        ],
    }
    report_token = store_report(report_data, 40.0, None, user_id=owner["id"], username="owner_user")

    from database import get_report
    rep = get_report(report_token)
    vuln_id = rep["result"]["vulnerabilities"][0]["id"]

    # Log in as the actual owner
    with client.session_transaction() as sess:
        sess["_user_id"] = str(owner["id"])
        sess["user_id"] = owner["id"]
        sess["username"] = "owner_user"
        sess["role"] = "analyst"

    # Authoritative verify-fix call
    res = client.post(
        f"/api/reports/vulnerabilities/{vuln_id}/verify-fix",
        json={"notes": "Reverse proxy updated with X-Frame-Options DENY directive."},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["vulnerability"]["is_fixed"] == 1
    assert body["vulnerability"]["triage_status"] == "Resolved"
    assert "verified" in body["vulnerability"]["triage_notes"].lower()

    # Verify persistent DB state reflects update
    rep_updated = get_report(report_token)
    updated_vuln = rep_updated["result"]["vulnerabilities"][0]
    assert updated_vuln["is_fixed"] is True
    assert updated_vuln["triage_status"] == "Resolved"


# ── 5. SEC-05 Sandbox Remediation Ownership Gate Tests ──────────────────────────

def test_sandbox_remediation_sec05_ownership_blocked():
    """SEC-05: User B submitting remediation referencing User A's sandbox is rejected."""
    from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES["sb_user_a_001"] = {
            "id": "sb_user_a_001",
            "user_id": 100,  # Owned by User A (ID 100)
            "vuln_type": "xss",
            "status": "running",
            "port": 5001,
        }

    content = {"vuln_type": "xss", "defense_concepts": ["csp"]}
    # User 200 (User B) attempts to verify remediation using User A's sandbox
    res = evaluate_remediation_submission(
        submission_text="Configured strict Content-Security-Policy.",
        content=content,
        metadata={"sandbox_id": "sb_user_a_001"},
        user_id=200,  # Attacker / Unauthorized User B
        vuln_type="xss",
    )
    assert res["score"] == 0.0
    assert res["is_verified"] == 0
    assert res["result"] == "failed"
    assert "ownership mismatch" in res["notes"].lower() or "sec-05" in res["notes"].lower()


def test_sandbox_remediation_owner_success():
    """Valid owner submitting remediation attempt with their own running sandbox succeeds."""
    from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK
    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES["sb_owner_002"] = {
            "id": "sb_owner_002",
            "user_id": 100,  # Owned by User 100
            "vuln_type": "xss",
            "status": "running",
            "port": 5002,
        }

    content = {"vuln_type": "xss", "defense_concepts": ["csp"]}
    res = evaluate_remediation_submission(
        submission_text="Configured strict Content-Security-Policy.",
        content=content,
        metadata={"sandbox_id": "sb_owner_002"},
        user_id=100,  # Actual owner
        vuln_type="xss",
    )
    assert res["score"] == 1.0
    assert res["is_verified"] == 1
    assert res["result"] == "passed"
    assert res["evaluation_status"] == "system_verified"
    assert res["evidence_type"] == "VERIFIED"
    assert "sandbox verification succeeded" in res["notes"].lower()

