"""Tests for Subscription Payment Hardening (fix/round3 item 2)."""

import os
import pytest
from unittest.mock import patch
from app import create_app
from db.subscriptions import set_subscription, get_subscription, verify_payment, record_payment
from db.users import create_user, get_user_by_username


from db.connection import init_db


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
    with app.test_client() as c:
        yield c


class TestPaymentHardening:
    def test_demo_mode_in_production_fails_startup(self, monkeypatch):
        """DEMO_MODE=true with FLASK_ENV=production must prevent app startup."""
        monkeypatch.setenv("FLASK_ENV", "production")
        monkeypatch.setenv("DEMO_MODE", "true")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-that-is-sufficiently-long-for-tests-12345")
        with pytest.raises(RuntimeError, match="CRITICAL SECURITY ERROR: DEMO_MODE cannot be enabled in production"):
            create_app()

    def test_bogus_payment_ref_pi_rejected(self, client):
        """Bogus transaction 'pi_AAAAAAAAAAAAAAAAAAAA' must be rejected (regex bypass fix)."""
        # Create non-admin user
        uname = "regular_user_pay1"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_test_mocksecret123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_AAAAAAAAAAAAAAAAAAAA"
            })
            assert resp.status_code in (400, 402)
            data = resp.get_json()
            assert data["ok"] is False
            sub = get_subscription(user["id"])
            assert sub["plan"] == "free"

    def test_reused_payment_reference_rejected(self, client):
        """Valid payment references cannot be reused across accounts or multiple times."""
        uname1 = "user_reuser_1"
        uname2 = "user_reuser_2"
        create_user(uname1, "SecurePassword123!", role="analyst")
        create_user(uname2, "SecurePassword123!", role="analyst")
        u1 = get_user_by_username(uname1)
        u2 = get_user_by_username(uname2)

        ref = "pi_validmockreference_123456"
        # Record payment as used by u1
        ok = record_payment(ref, u1["id"], "pro", 12000.0, "DZD")
        assert ok is True

        # Second attempt to record same ref must fail
        ok2 = record_payment(ref, u2["id"], "pro", 12000.0, "DZD")
        assert ok2 is False

        # Upgrade request with reused ref must be rejected
        with client.session_transaction() as sess:
            sess["_user_id"] = str(u2["id"])

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_test_mocksecret123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": ref
            })
            assert resp.status_code in (400, 402)
            data = resp.get_json()
            assert data["ok"] is False

    def test_no_provider_restricts_to_admin(self, client):
        """If no gateway secret is configured, paid upgrades are restricted to admin only."""
        uname = "regular_no_provider"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        env_without_secret = {k: v for k, v in os.environ.items() if k not in ("PAYMENT_GATEWAY_SECRET", "STRIPE_SECRET_KEY")}
        with patch.dict(os.environ, env_without_secret, clear=True):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_someref"
            })
            assert resp.status_code in (402, 403)
            data = resp.get_json()
            assert data["ok"] is False
