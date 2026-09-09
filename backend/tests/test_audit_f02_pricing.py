"""F-02 Tests: Pricing plans and subscription upgrade flow."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-f02-testing")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_f02.db")
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
    )
    with flask_app.app_context():
        db.init_db()
        db.create_user("plan_user", "TestPass123!", role="viewer")
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestSubscriptionPricing:
    def test_list_plans_public_endpoint(self, app):
        """F-02: Public endpoint GET /api/subscription/plans lists all available tiers."""
        client = app.test_client()
        res = client.get("/api/subscription/plans")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("ok") is True
        plans = data.get("plans", {})
        assert "free" in plans
        assert "pro" in plans
        assert "enterprise" in plans
        assert plans["pro"]["max_scans_month"] == 20

    def test_upgrade_requires_authentication(self, app):
        """F-02: Unauthenticated POST /api/subscription/upgrade returns 401."""
        client = app.test_client()
        res = client.post("/api/subscription/upgrade", json={"plan": "pro"})
        assert res.status_code in (401, 302)

    def test_upgrade_invalid_plan_returns_400(self, app):
        """F-02: POST with an unknown plan returns 400 Bad Request."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "plan_user", "password": "TestPass123!"})

        res = client.post("/api/subscription/upgrade", json={"plan": "mega_hyper_plan"})
        assert res.status_code == 400
        data = res.get_json()
        assert "Invalid plan" in data.get("error", "")

    def test_upgrade_plan_success_flow(self, app):
        """F-02: Successfully upgrade to Pro plan, verifying quota increase and event logging."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "plan_user", "password": "TestPass123!"})

        # Initial subscription should be free
        res_initial = client.get("/api/subscription")
        assert res_initial.status_code == 200
        assert res_initial.get_json()["plan"] == "free"
        assert res_initial.get_json()["max_scans_month"] == 1

        # Upgrade to Pro
        res_upgrade = client.post("/api/subscription/upgrade", json={"plan": "pro"})
        assert res_upgrade.status_code == 200
        data = res_upgrade.get_json()
        assert data.get("ok") is True
        assert data.get("subscription", {}).get("plan") == "pro"
        assert data.get("subscription", {}).get("max_scans_month") == 20

        # Check subsequent GET /api/subscription reflects new plan
        res_after = client.get("/api/subscription")
        assert res_after.status_code == 200
        sub = res_after.get_json()
        assert sub["plan"] == "pro"
        assert sub["max_scans_month"] == 20
        assert sub["remaining"] == 20
