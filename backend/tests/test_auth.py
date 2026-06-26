"""Tests for authentication endpoints — register, login, logout, profile."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_auth.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("WTF_CSRF_ENABLED", "false")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SERVER_NAME="localhost",
        SESSION_COOKIE_SECURE=False,
    )
    with flask_app.app_context():
        db.init_db()
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client, username="admin", password="Admin@2024!"):
    return client.post(
        "/api/login",
        json={"username": username, "password": password},
        content_type="application/json",
    )


class TestLogin:
    def test_valid_credentials_succeed(self, client):
        r = _login(client)
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("ok") is True

    def test_wrong_password_fails(self, client):
        r = _login(client, password="WrongPass!")
        assert r.status_code in (401, 400)
        data = r.get_json()
        assert data.get("ok") is not True

    def test_unknown_user_fails(self, client):
        r = _login(client, username="nobody", password="anything")
        assert r.status_code in (401, 400)

    def test_missing_fields_rejected(self, client):
        r = client.post("/api/login", json={}, content_type="application/json")
        assert r.status_code in (400, 422)


class TestProtectedRoute:
    def test_unauthenticated_dashboard_returns_401(self, client):
        r = client.get("/api/dashboard")
        assert r.status_code == 401

    def test_authenticated_dashboard_returns_200(self, client):
        _login(client)
        r = client.get("/api/dashboard")
        assert r.status_code == 200

    def test_admin_stats_forbidden_for_analyst(self, client, app):
        with app.app_context():
            db.create_user("analyst2", "Analyst@2024!", role="analyst")
        _login(client, "analyst2", "Analyst@2024!")
        r = client.get("/api/admin/stats")
        assert r.status_code == 403

    def test_admin_stats_allowed_for_admin(self, client):
        _login(client, "admin", "Admin@2024!")
        r = client.get("/api/admin/stats")
        assert r.status_code == 200


class TestLogout:
    def test_logout_clears_session(self, client):
        _login(client)
        r = client.post("/api/logout")
        assert r.status_code == 200
        # After logout, dashboard should require auth again
        r2 = client.get("/api/dashboard")
        assert r2.status_code == 401


class TestProfile:
    def test_profile_returns_user_info(self, client):
        _login(client)
        r = client.get("/api/profile")
        assert r.status_code == 200
        data = r.get_json()
        assert "username" in data or "user" in data
