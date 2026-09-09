"""H-01 Security Regression Tests: SSRF and Target-Lock Guard on /start-scan."""
import os
import sys
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_h01.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
    )
    with flask_app.app_context():
        db.init_db()
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


@pytest.fixture()
def client_factory(app):
    def _make_client(username, password="TestUser@2024!", role="analyst", allowed_target=None):
        with app.app_context():
            db.create_user(
                username=username,
                password=password,
                role=role,
                allowed_target=allowed_target,
            )
        client = app.test_client()
        client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            content_type="application/json",
        )
        return client
    return _make_client


class TestStartScanSecurityGuards:
    def test_locked_target_user_blocked_from_arbitrary_targets(self, client_factory):
        """H-01 (A): User locked to 'example.com' attempting /start-scan against 169.254.169.254 MUST be rejected with 403."""
        client = client_factory(
            username="restricted_analyst",
            role="analyst",
            allowed_target="example.com",
        )
        form_data = {
            "target": "169.254.169.254",
            "scan_type": "network_ext",
            "criticality": "1",
            "legal_disclaimer": "y",
        }
        resp = client.post("/start-scan", data=form_data)
        assert resp.status_code == 403
        data = resp.get_json() or {}
        assert data.get("forbidden") is True or data.get("ssrf_blocked") is True

    def test_unlocked_user_blocked_from_ssrf_metadata_ip(self, client_factory):
        """H-01 (B): Normal user attempting /start-scan against cloud metadata (169.254.169.254) MUST be rejected by SSRF guard."""
        client = client_factory(
            username="normal_analyst",
            role="analyst",
            allowed_target=None,
        )
        for scan_type in ["network_ext", "web", "server_ext"]:
            form_data = {
                "target": "169.254.169.254",
                "scan_type": scan_type,
                "criticality": "1",
                "legal_disclaimer": "y",
            }
            resp = client.post("/start-scan", data=form_data)
            assert resp.status_code == 403, f"Failed for scan_type {scan_type}"
            data = resp.get_json() or {}
            assert data.get("ssrf_blocked") is True

    def test_unlocked_user_blocked_from_localhost(self, client_factory):
        """H-01 (C): Normal user attempting /start-scan against 127.0.0.1 MUST be rejected by SSRF guard."""
        client = client_factory(
            username="normal_analyst2",
            role="analyst",
            allowed_target=None,
        )
        form_data = {
            "target": "127.0.0.1",
            "scan_type": "web",
            "criticality": "1",
            "legal_disclaimer": "y",
        }
        resp = client.post("/start-scan", data=form_data)
        assert resp.status_code == 403
        data = resp.get_json() or {}
        assert data.get("ssrf_blocked") is True

    def test_legitimate_scan_with_allowed_target_passes_guard(self, client_factory):
        """H-01 (D): User with allowed target 'scanme.nmap.org' scanning their assigned target passes target guard."""
        client = client_factory(
            username="valid_analyst",
            role="analyst",
            allowed_target="scanme.nmap.org",
        )
        with patch("blueprints.scans.run_nmap_scan", return_value={"vulnerabilities": []}):
            form_data = {
                "target": "scanme.nmap.org",
                "scan_type": "network_ext",
                "criticality": "1",
                "legal_disclaimer": "y",
            }
            resp = client.post("/start-scan", data=form_data)
            assert resp.status_code == 200
