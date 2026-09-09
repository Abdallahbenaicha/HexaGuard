"""H-03 Security Tests: Self-registration restrictions and rate limiting."""
import os
import sys
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-h03-testing")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_h03.db")
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


class TestSelfRegistrationRestrictions:
    def test_newly_registered_user_cannot_run_scans_without_approval(self, app):
        """H-03: Newly self-registered user MUST NOT have run_scan permissions and cannot initiate scans."""
        client = app.test_client()

        # 1. Register self
        reg_resp = client.post(
            "/api/auth/register",
            json={
                "username": "newbie_user",
                "email": "newbie@example.com",
                "password": "Password123!",
            },
        )
        assert reg_resp.status_code == 201

        # Check DB user role and permissions
        user = db.get_user_by_username("newbie_user")
        assert user is not None
        assert user["role"] == "viewer"
        assert "run_scan" not in (user.get("permissions") or [])

        # 2. Log in with the new account
        login_resp = client.post(
            "/api/auth/login",
            json={"username": "newbie_user", "password": "Password123!"},
        )
        assert login_resp.status_code == 200

        # 3. Attempt to run a scan - MUST be rejected with 403 Forbidden
        with patch("blueprints.scans.run_web_scan", return_value={"vulnerabilities": []}):
            scan_resp = client.post(
                "/scan_url",
                json={"url": "https://example.com"},
            )
            assert scan_resp.status_code == 403
            data = scan_resp.get_json() or {}
            assert "صلاحية غير كافية" in data.get("error", "") or "Forbidden" in data.get("error", "") or "Access denied" in data.get("error", "")

    def test_admin_approval_grants_scan_permission(self, app):
        """H-03 (B): Admin manually promoting viewer to analyst enables scanning."""
        client = app.test_client()

        # Register self
        client.post(
            "/api/auth/register",
            json={
                "username": "promoted_user",
                "email": "promoted@example.com",
                "password": "Password123!",
            },
        )
        user = db.get_user_by_username("promoted_user")

        # Admin updates role to analyst
        db.update_user(user["id"], role="analyst", permissions=["run_scan", "view_reports"])

        # Log in as promoted user
        client.post(
            "/api/auth/login",
            json={"username": "promoted_user", "password": "Password123!"},
        )

        # Scan should now pass permission check
        with patch("blueprints.scans.run_web_scan", return_value={"vulnerabilities": []}):
            scan_resp = client.post(
                "/scan_url",
                json={"url": "https://example.com"},
            )
            assert scan_resp.status_code == 200
