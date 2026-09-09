"""T-01 Tests: Strict local environment gate (DEPLOYMENT_MODE=local) for Bounty Radar."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-t01-testing")

import database as db


@pytest.fixture()
def app_factory(tmp_path, monkeypatch):
    def _make_app(deployment_mode: str):
        db_file = str(tmp_path / f"test_t01_{deployment_mode}.db")
        monkeypatch.setenv("DB_PATH", db_file)
        monkeypatch.setenv("FLASK_ENV", "testing")
        monkeypatch.setenv("ENABLE_LIVE_BOUNTY_SCANNING", "true")
        monkeypatch.setenv("DEPLOYMENT_MODE", deployment_mode)

        if hasattr(db._local, "conn"):
            del db._local.conn
        db.DB_PATH = db_file

        from app import create_app
        flask_app = create_app()
        flask_app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
        )
        with flask_app.app_context():
            db.init_db()
            db.create_user("bounty_admin", "TestPass123!", role="admin")

        return flask_app

    return _make_app


class TestBountyLocalGate:
    def test_bounty_routes_return_404_in_cloud_mode(self, app_factory):
        """T-01: All bounty routes MUST return 404 when DEPLOYMENT_MODE != 'local'."""
        app = app_factory(deployment_mode="cloud")
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "bounty_admin", "password": "TestPass123!"})

        # Test targets endpoint returns 404
        res1 = client.get("/api/admin/bounty-targets")
        assert res1.status_code == 404
        data1 = res1.get_json()
        assert "restricted to local deployment" in data1.get("error", "").lower()

        # Test verify policy returns 404
        res2 = client.post("/api/bounty/verify-policy", json={"target": "example.com"})
        assert res2.status_code == 404

    def test_bounty_routes_accessible_in_local_mode(self, app_factory):
        """T-01: Bounty routes are accessible (not blocked by 404) when DEPLOYMENT_MODE == 'local'."""
        app = app_factory(deployment_mode="local")
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "bounty_admin", "password": "TestPass123!"})

        res = client.get("/api/admin/bounty-targets")
        # In local mode, should NOT return 404
        assert res.status_code != 404
        assert res.status_code == 200

    def test_config_deployment_mode_endpoint(self, app_factory):
        """T-01: GET /api/config/deployment-mode exposes the deployment mode."""
        app = app_factory(deployment_mode="local")
        client = app.test_client()

        res = client.get("/api/config/deployment-mode")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("deployment_mode") == "local"
        assert data.get("is_local") is True
