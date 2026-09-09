"""H-02 Security Tests: CSRF Enforcement on Scan-Triggering Routes."""
import os
import sys
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-csrf-testing")

import database as db


@pytest.fixture()
def csrf_app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_csrf.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=True,  # Active CSRF protection
        WTF_CSRF_CHECK_DEFAULT=True,
        SESSION_COOKIE_SECURE=False,
    )
    with flask_app.app_context():
        db.init_db()
        db.create_user("csrf_analyst", "TestPass123!", role="admin")
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


@pytest.fixture()
def logged_in_client(csrf_app):
    client = csrf_app.test_client()
    # Login via session
    resp = client.post(
        "/api/auth/login",
        json={"username": "csrf_analyst", "password": "TestPass123!"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    return client


class TestCsrfProtection:
    def test_post_scan_without_csrf_token_rejected(self, logged_in_client):
        """H-02 (A): Session-authenticated POST to scan routes without CSRF token MUST return 400 CSRF error."""
        with patch("blueprints.scans.run_web_scan", return_value={"vulnerabilities": []}):
            res = logged_in_client.post(
                "/scan_url",
                json={"url": "https://example.com"},
            )
            assert res.status_code == 400
            assert b"CSRF" in res.data or b"csrf" in res.data

    def test_extra_scans_without_csrf_token_rejected(self, logged_in_client):
        """H-02 (B): Session-authenticated POST to extra scan routes without CSRF token MUST return 400."""
        res = logged_in_client.post(
            "/scan_dns",
            json={"target": "example.com"},
        )
        assert res.status_code == 400
        assert b"CSRF" in res.data or b"csrf" in res.data

    def test_post_scan_with_valid_csrf_token_accepted(self, logged_in_client):
        """H-02 (C): Session-authenticated POST with valid X-CSRFToken header passes CSRF verification."""
        # Get CSRF token from /api/auth/me or session
        me_resp = logged_in_client.get("/api/auth/me")
        csrf_token = me_resp.headers.get("X-CSRFToken")
        if not csrf_token:
            for cookie in logged_in_client.cookie_jar:
                if cookie.name == "csrftoken":
                    csrf_token = cookie.value
                    break
        assert csrf_token is not None, "CSRF token must be exposed in header or cookie"

        with patch("blueprints.scans.run_web_scan", return_value={"vulnerabilities": []}):
            res = logged_in_client.post(
                "/scan_url",
                json={"url": "https://example.com"},
                headers={"X-CSRFToken": csrf_token},
            )
            assert res.status_code == 200
