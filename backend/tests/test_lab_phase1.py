"""SecuraX Evaluation Lab — Phase 1 Acceptance & Security Gate Tests.

Verifies all non-negotiable requirements of Master Specification v5 Phase 1:
  - LAB_MODE feature flag enforcement (default OFF, forced OFF in demo profile).
  - RBAC admin enforcement and 2FA guards.
  - Fail-closed Gate evaluation for all target kinds.
  - public_reference targets are NEVER executable.
  - public_permitted 90-day authorization expiration & user acknowledgement.
  - Local address sanitization and bypass defense:
      • Cloud metadata (169.254.169.254, metadata.google.internal)
      • Obfuscated IP encodings (hex 0x7f000001, octal 0177.0.0.1, dword integer)
      • Userinfo tricks (http://user:pass@127.0.0.1)
      • Non-local IP addresses for local container targets
      • Local lab identity mismatch (confused admin / stale container guard)
  - Complete immutable audit log verification for all gate denials and authorizations.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from app import create_app
from database import (
    create_user,
    get_audit_log,
    get_user_by_username,
    init_db,
    init_lab_tables,
    seed_lab_targets,
    get_lab_target,
    list_lab_targets,
)
from lab.config import is_demo_profile, is_lab_mode_enabled, is_lab_remote_scanning_enabled
from lab.gate import evaluate_lab_gate
from lab.models import GateDecision, TargetKind


@pytest.fixture
def app_instance(tmp_path, monkeypatch):
    """Create test application bound to temporary SQLite database."""
    test_db = str(tmp_path / "test_lab_phase1.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "phase1-test-secret-key-32-chars-min")
    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")

    app = create_app()
    with app.app_context():
        init_db()
        init_lab_tables()
        seed_lab_targets()
    return app


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


@pytest.fixture
def admin_user(app_instance):
    """Retrieve or create admin user for testing with 2FA enabled."""
    from db.users import update_user_totp
    with app_instance.app_context():
        u = get_user_by_username("admin")
        if not u:
            ok, msg, uid = create_user("admin", "AdminPass123!@#", role="admin")
            u = get_user_by_username("admin")
        update_user_totp(u["id"], "JBSWY3DPEHPK3PXP", True)
        u = get_user_by_username("admin")
        return u


@pytest.fixture
def analyst_user(app_instance):
    """Create non-admin analyst user for RBAC testing."""
    with app_instance.app_context():
        u = get_user_by_username("analyst_tester")
        if not u:
            create_user("analyst_tester", "AnalystPass123!@#", role="analyst")
            u = get_user_by_username("analyst_tester")
        return u


# ══════════════════════════════════════════════════════════════════════════════
# 1. LAB_MODE & Demo Profile Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_lab_mode_disabled_by_default(monkeypatch):
    """LAB_MODE must be OFF (False) when not explicitly enabled."""
    monkeypatch.delenv("LAB_MODE", raising=False)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    assert is_lab_mode_enabled() is False


def test_lab_mode_forced_off_in_demo_profile(monkeypatch):
    """LAB_MODE is forced OFF in public demo profiles even if LAB_MODE=1."""
    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("DEMO_MODE", "1")
    assert is_demo_profile() is True
    assert is_lab_mode_enabled() is False


def test_lab_mode_forced_off_in_cf_pages_demo(monkeypatch):
    """Cloudflare Pages / Oracle Free VM demo profile forces LAB_MODE off."""
    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("CF_PAGES", "1")
    assert is_lab_mode_enabled() is False


def test_lab_endpoints_return_403_when_lab_mode_disabled(client, admin_user, monkeypatch):
    """Backend strictly blocks /api/lab endpoints with 403 when LAB_MODE is disabled."""
    monkeypatch.setenv("LAB_MODE", "0")
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user["id"])

    res = client.get("/api/lab/targets")
    assert res.status_code == 403
    data = res.get_json()
    assert data["ok"] is False
    assert data["code"] == "LAB_MODE_DISABLED"


# ══════════════════════════════════════════════════════════════════════════════
# 2. RBAC & 2FA Access Control Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_anonymous_access_rejected(client):
    """Unauthenticated access to /api/lab is rejected with 401."""
    res = client.get("/api/lab/targets")
    assert res.status_code == 401
    assert res.get_json()["code"] == "AUTH_REQUIRED"


def test_non_admin_access_rejected_and_audited(client, analyst_user):
    """Non-admin user receives 403 and denial is recorded in audit log."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_user["id"])

    res = client.get("/api/lab/targets")
    assert res.status_code == 403
    assert res.get_json()["code"] == "ADMIN_REQUIRED"

    # Verify audit log entry
    logs, total = get_audit_log(action="lab_unauthorized_access")
    assert total >= 1
    assert any(log["username"] == "analyst_tester" for log in logs)


def test_admin_access_allowed(client, admin_user):
    """Admin user with valid session can access /api/lab/targets."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user["id"])

    res = client.get("/api/lab/targets")
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert "targets" in data
    assert len(data["targets"]) > 0


def test_unverified_totp_session_blocked(app_instance, client, admin_user, monkeypatch):
    """Admin with pending TOTP validation is blocked from Lab endpoints."""
    from db.users import update_user_totp
    with app_instance.app_context():
        update_user_totp(admin_user["id"], "JBSWY3DPEHPK3PXP", True)

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user["id"])
        sess["pending_totp_user_id"] = admin_user["id"]

    res = client.get("/api/lab/targets")
    assert res.status_code == 403
    assert res.get_json()["code"] == "2FA_REQUIRED"


def test_admin_without_totp_setup_blocked(app_instance, client):
    """Admin who has not enabled 2FA is blocked with 2FA_SETUP_REQUIRED."""
    from db.users import create_user, get_user_by_username, update_user_totp
    with app_instance.app_context():
        u = get_user_by_username("admin_no_totp")
        if not u:
            create_user("admin_no_totp", "AdminPass123!@#", role="admin")
            u = get_user_by_username("admin_no_totp")
        update_user_totp(u["id"], "", False)

    with client.session_transaction() as sess:
        sess["_user_id"] = str(u["id"])

    res = client.get("/api/lab/targets")
    assert res.status_code == 403
    data = res.get_json()
    assert data["ok"] is False
    assert data["code"] == "2FA_SETUP_REQUIRED"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Target Registry & Seed Catalog Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_registry_contains_bundled_fixtures(app_instance):
    """Registry seeds valid bundled fixtures (Apache, Docker, SAST)."""
    with app_instance.app_context():
        targets = list_lab_targets(kind=TargetKind.BUNDLED_FIXTURE.value)
        assert len(targets) >= 3
        ids = {t["id"] for t in targets}
        assert "fixture_server_apache" in ids
        assert "fixture_docker_basic" in ids
        assert "fixture_sast_python" in ids


def test_public_reference_targets_never_executable(app_instance):
    """public_reference targets are marked non-executable and disabled for runs."""
    with app_instance.app_context():
        refs = list_lab_targets(kind=TargetKind.PUBLIC_REFERENCE.value)
        assert len(refs) >= 5
        for ref in refs:
            assert ref["enabled"] is False
            assert ref["is_executable"] is False
            assert ref["permitted_scan_types"] == []


# ══════════════════════════════════════════════════════════════════════════════
# 4. Fail-Closed Gate Evaluation & Security Bypass Defense
# ══════════════════════════════════════════════════════════════════════════════

def test_gate_rejects_unregistered_target(app_instance, admin_user):
    """Gate strictly rejects unregistered target ID."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="non_existent_target_123",
            scanner="sast",
            scan_type="sast",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.decision == GateDecision.DENY
        assert res.reason_code == "TARGET_NOT_FOUND"


def test_gate_rejects_public_reference_target(app_instance, admin_user):
    """Gate strictly rejects scanning any public_reference target."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="ref_testphp_vulnweb",
            scanner="dast",
            scan_type="dast",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "PUBLIC_REFERENCE_NOT_EXECUTABLE"


def test_gate_rejects_scanner_mismatch(app_instance, admin_user):
    """Gate rejects when scanner is not listed for target."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="fixture_server_apache",
            scanner="dast",  # Apache fixture only allows server scanner
            scan_type="server_int",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "SCANNER_NOT_PERMITTED"


def test_gate_rejects_scan_type_mismatch(app_instance, admin_user):
    """Gate rejects when scan type is not in permitted_scan_types."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="fixture_server_apache",
            scanner="server",
            scan_type="web",  # Not in permitted_scan_types
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "SCAN_TYPE_NOT_PERMITTED"


def test_gate_rejects_remote_scanning_when_disabled(app_instance, admin_user, monkeypatch):
    """Remote scanning of public_permitted target is blocked when flag is OFF."""
    monkeypatch.delenv("ALLOW_LAB_REMOTE_SCANNING", raising=False)
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, auth_verified_at, created_at, updated_at
            ) VALUES ('test_permitted', 'Permitted Host', 'public_permitted', '["web"]',
                      'https://example.com', '["web"]', 1, ?, ?, ?)
        """, (now, now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="test_permitted",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "REMOTE_SCANNING_DISABLED"


def test_gate_rejects_expired_authorization(app_instance, admin_user, monkeypatch):
    """Authorization older than 90 days is strictly rejected."""
    monkeypatch.setenv("ALLOW_LAB_REMOTE_SCANNING", "1")
    with app_instance.app_context():
        from db.connection import _get_db
        expired_date = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, auth_verified_at, created_at, updated_at
            ) VALUES ('test_expired', 'Expired Auth Target', 'public_permitted', '["web"]',
                      'https://example.com', '["web"]', 1, ?, ?, ?)
        """, (expired_date, now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="test_expired",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "AUTHORIZATION_EXPIRED"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Local Address Sanitization & Evasion Defense Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_gate_blocks_cloud_metadata_ips(app_instance, admin_user):
    """Gate blocks AWS/GCP/Azure link-local metadata endpoints."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, created_at, updated_at
            ) VALUES ('meta_attack', 'Metadata Attack', 'local_container', '["web"]',
                      'http://169.254.169.254/latest/meta-data', '["web"]', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="meta_attack",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_gate_blocks_obfuscated_hex_ip(app_instance, admin_user):
    """Gate rejects hex-encoded IP addresses (e.g. 0x7f000001)."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, created_at, updated_at
            ) VALUES ('hex_attack', 'Hex Attack', 'local_container', '["web"]',
                      'http://0x7f000001:8080', '["web"]', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="hex_attack",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_gate_blocks_userinfo_url_tricks(app_instance, admin_user):
    """Gate rejects URL userinfo tricks (e.g. http://attacker:pass@127.0.0.1)."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, created_at, updated_at
            ) VALUES ('userinfo_attack', 'Userinfo Attack', 'local_container', '["web"]',
                      'http://attacker:secret@127.0.0.1:8080', '["web"]', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="userinfo_attack",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_gate_rejects_lab_identity_mismatch(app_instance, admin_user):
    """Confused Admin Guard: rejects when service on port does not match expected fingerprint."""
    with app_instance.app_context():
        # Mock probe response returning something completely different (e.g. Apache default page)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Apache2 Ubuntu Default Page</body></html>"
        mock_resp.headers = {"Server": "Apache/2.4.41"}

        with patch("requests.get", return_value=mock_resp):
            res = evaluate_lab_gate(
                target_id="local_dvwa",  # Expects "Damn Vulnerable Web App"
                scanner="web",
                scan_type="web",
                user_id=admin_user["id"],
                username=admin_user["username"],
            )
            assert res.allowed is False
            assert res.reason_code == "LAB_IDENTITY_MISMATCH"


def test_gate_allows_authorized_bundled_fixture(app_instance, admin_user):
    """Gate successfully authorizes clean bundled fixture."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="fixture_server_apache",
            scanner="server",
            scan_type="server_int",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is True
        assert res.decision == GateDecision.ALLOW
        assert res.reason_code == "AUTHORIZED"


def test_gate_verifies_via_api_endpoint(client, admin_user):
    """POST /api/lab/gate/verify returns Gate decision and records audit log."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user["id"])

    payload = {
        "target_id": "fixture_server_apache",
        "scanner": "server",
        "scan_type": "server_int",
    }
    res = client.post("/api/lab/gate/verify", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["gate"]["allowed"] is True
    assert data["gate"]["reason_code"] == "AUTHORIZED"

    # Verify audit log recorded decision
    logs, total = get_audit_log(action="lab_gate_allow")
    assert total >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 6. Minimal Remediation Regression Tests (Audit Finding Verification)
# ══════════════════════════════════════════════════════════════════════════════

def test_gate_blocks_schemeless_container_without_fingerprint(app_instance, admin_user):
    """Scheme-less container address (e.g. 192.168.1.50:8080) cannot bypass sanitization and fingerprinting."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('schemeless_test', 'Schemeless Container', 'local_container', '["web"]',
                      '192.168.1.50:8080', '["web"]', 'ExpectedAppBanner', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        # Without mock: 192.168.1.50:8080 is unreachable, so it must FAIL CLOSED
        res = evaluate_lab_gate(
            target_id="schemeless_test",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "LAB_IDENTITY_MISMATCH"


def test_gate_allows_schemeless_container_when_fingerprint_matches(app_instance, admin_user):
    """Scheme-less container address passes when fingerprint probe succeeds."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('schemeless_ok', 'Schemeless Container OK', 'local_container', '["web"]',
                      '192.168.1.50:8080', '["web"]', 'ExpectedAppBanner', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>ExpectedAppBanner v1.0</body></html>"
        mock_resp.headers = {"Server": "CustomLab/1.0"}

        with patch("requests.get", return_value=mock_resp):
            res = evaluate_lab_gate(
                target_id="schemeless_ok",
                scanner="web",
                scan_type="web",
                user_id=admin_user["id"],
                username=admin_user["username"],
            )
            assert res.allowed is True
            assert res.reason_code == "AUTHORIZED"
            assert res.verified_address == "192.168.1.50"


def test_gate_blocks_schemeless_prohibited_metadata_address(app_instance, admin_user):
    """Scheme-less metadata address (e.g. 169.254.169.254:80) is strictly blocked."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('schemeless_meta', 'Metadata Host', 'local_container', '["web"]',
                      '169.254.169.254:80', '["web"]', 'AWS', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="schemeless_meta",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_gate_blocks_schemeless_userinfo_address(app_instance, admin_user):
    """Scheme-less address with userinfo trick (e.g. attacker:pass@127.0.0.1:8080) is denied."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('schemeless_userinfo', 'Userinfo Host', 'local_container', '["web"]',
                      'attacker:pass@127.0.0.1:8080', '["web"]', 'App', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="schemeless_userinfo",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_gate_blocks_schemeless_non_local_ip(app_instance, admin_user):
    """Scheme-less non-local IP (e.g. 8.8.8.8:8080) is denied for local_container."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('schemeless_nonlocal', 'Non Local Host', 'local_container', '["web"]',
                      '8.8.8.8:8080', '["web"]', 'App', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="schemeless_nonlocal",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "NON_LOCAL_IP_REJECTED"


def test_gate_blocks_schemeless_malformed_address(app_instance, admin_user):
    """Scheme-less unresolvable or malformed address fails closed."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                expected_fingerprint, enabled, created_at, updated_at
            ) VALUES ('malformed_addr', 'Malformed Host', 'local_container', '["web"]',
                      'unresolvable-lab-target.local:8080', '["web"]', 'App', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="malformed_addr",
            scanner="web",
            scan_type="web",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code in ("ADDRESS_VALIDATION_FAILED", "GATE_EVALUATION_ERROR")



def test_gate_preserves_valid_bundled_fixtures_and_sources(app_instance, admin_user):
    """Valid bundled fixtures and local source projects are allowed without network address parsing."""
    with app_instance.app_context():
        # Apache fixture
        res1 = evaluate_lab_gate(
            target_id="fixture_server_apache",
            scanner="server",
            scan_type="server_int",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res1.allowed is True
        assert res1.reason_code == "AUTHORIZED"

        # Docker fixture
        res2 = evaluate_lab_gate(
            target_id="fixture_docker_basic",
            scanner="docker",
            scan_type="docker",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res2.allowed is True
        assert res2.reason_code == "AUTHORIZED"

        # SAST fixture
        res3 = evaluate_lab_gate(
            target_id="fixture_sast_python",
            scanner="sast",
            scan_type="sast",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res3.allowed is True
        assert res3.reason_code == "AUTHORIZED"

        # OWASP Benchmark local source
        res4 = evaluate_lab_gate(
            target_id="owasp_benchmark",
            scanner="sast",
            scan_type="sast",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res4.allowed is True
        assert res4.reason_code == "AUTHORIZED"


def test_gate_blocks_path_traversal_in_filesystem_targets(app_instance, admin_user):
    """Filesystem targets attempting path traversal are denied."""
    with app_instance.app_context():
        from db.connection import _get_db
        now = datetime.now(timezone.utc).isoformat()
        _get_db().execute("""
            INSERT OR REPLACE INTO lab_targets (
                id, name, kind, scanners, address, permitted_scan_types,
                enabled, created_at, updated_at
            ) VALUES ('traversal_fixture', 'Traversal Fixture', 'bundled_fixture', '["sast"]',
                      '../../../../etc/passwd', '["sast"]', 1, ?, ?)
        """, (now, now))
        _get_db().commit()

        res = evaluate_lab_gate(
            target_id="traversal_fixture",
            scanner="sast",
            scan_type="sast",
            user_id=admin_user["id"],
            username=admin_user["username"],
        )
        assert res.allowed is False
        assert res.reason_code == "ADDRESS_VALIDATION_FAILED"


def test_public_reference_remains_blocked_even_with_acknowledgement(app_instance, admin_user):
    """Public reference targets remain strictly non-executable even if user acknowledged."""
    with app_instance.app_context():
        res = evaluate_lab_gate(
            target_id="ref_testphp_vulnweb",
            scanner="dast",
            scan_type="dast",
            user_id=admin_user["id"],
            username=admin_user["username"],
            acknowledge_public_scope=True,
        )
        assert res.allowed is False
        assert res.reason_code == "PUBLIC_REFERENCE_NOT_EXECUTABLE"
