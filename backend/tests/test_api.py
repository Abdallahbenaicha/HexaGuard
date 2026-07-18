"""Integration tests for scan + report + scheduled scan API endpoints."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_api.db")
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
def auth_client(app):
    client = app.test_client()
    client.post(
        "/api/login",
        json={"username": "admin", "password": "Admin@2024!"},
        content_type="application/json",
    )
    return client


class TestHealthEndpoint:
    def test_health_returns_ok(self, app):
        client = app.test_client()
        r = client.get("/health")
        assert r.status_code == 200


class TestScanJobsEndpoints:
    def test_jobs_list_empty_initially(self, auth_client):
        r = auth_client.get("/api/scan/jobs")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data.get("jobs"), list)

    def test_single_job_404_for_unknown(self, auth_client):
        r = auth_client.get("/api/scan/job/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_scan_job_requires_auth(self, app):
        client = app.test_client()
        r = client.get("/api/scan/jobs")
        assert r.status_code == 401


class TestScheduledScansEndpoints:
    def test_list_scheduled_empty(self, auth_client):
        r = auth_client.get("/api/scheduled-scans")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["scheduled"] == []

    def test_create_scheduled_scan(self, auth_client):
        r = auth_client.post(
            "/api/scheduled-scans",
            json={"scan_type": "web", "target": "example.com", "cron_expr": "daily"},
            content_type="application/json",
        )
        assert r.status_code == 201
        data = r.get_json()
        assert data["ok"] is True
        assert data["id"] > 0

    def test_create_invalid_scan_type_rejected(self, auth_client):
        r = auth_client.post(
            "/api/scheduled-scans",
            json={"scan_type": "evil", "target": "x.com"},
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_create_missing_target_rejected(self, auth_client):
        r = auth_client.post(
            "/api/scheduled-scans",
            json={"scan_type": "web"},
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_delete_scheduled_scan(self, auth_client):
        # Create first
        r = auth_client.post(
            "/api/scheduled-scans",
            json={"scan_type": "ssl", "target": "secure.com", "cron_expr": "weekly"},
            content_type="application/json",
        )
        sched_id = r.get_json()["id"]
        # Delete
        r2 = auth_client.delete(f"/api/scheduled-scans/{sched_id}")
        assert r2.status_code == 200
        # Verify gone
        r3 = auth_client.get("/api/scheduled-scans")
        assert r3.get_json()["scheduled"] == []

    def test_toggle_scheduled_scan(self, auth_client):
        r = auth_client.post(
            "/api/scheduled-scans",
            json={"scan_type": "web", "target": "toggle.com"},
            content_type="application/json",
        )
        sched_id = r.get_json()["id"]
        r2 = auth_client.patch(
            f"/api/scheduled-scans/{sched_id}",
            json={"is_active": False},
            content_type="application/json",
        )
        assert r2.status_code == 200
        assert r2.get_json()["is_active"] is False


class TestReportsEndpoints:
    def test_reports_list_returns_200(self, auth_client):
        r = auth_client.get("/api/reports")
        assert r.status_code == 200

    def test_unknown_report_returns_404(self, auth_client):
        r = auth_client.get("/api/reports/nonexistenttoken123")
        assert r.status_code == 404


class TestSecurityHeaders:
    def test_x_content_type_options_present(self, app):
        client = app.test_client()
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options_present(self, app):
        client = app.test_client()
        r = client.get("/health")
        assert "X-Frame-Options" in r.headers

    def test_csp_header_present(self, app):
        client = app.test_client()
        r = client.get("/health")
        assert "Content-Security-Policy" in r.headers
