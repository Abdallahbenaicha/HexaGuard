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

    def test_bogus_payment_ref_pi_rejected(self, client, monkeypatch):
        """Bogus transaction 'pi_AAAAAAAAAAAAAAAAAAAA' must be rejected (regex bypass fix)."""
        import db.subscriptions
        def _mock_raise(ref, sec):
            raise RuntimeError("Payment intent not found")
        monkeypatch.setattr(db.subscriptions, "_fetch_intent", _mock_raise)

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

        env_without_secret = {k: v for k, v in os.environ.items() if k not in ("PAYMENT_GATEWAY_SECRET", "STRIPE_SECRET_KEY", "TESTING", "FLASK_ENV")}
        client.application.config["WTF_CSRF_ENABLED"] = False
        with patch.dict(os.environ, env_without_secret, clear=True):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_someref"
            })
            assert resp.status_code in (402, 403)
            data = resp.get_json()
            assert data["ok"] is False

    def test_payment_path_traversal_ref_rejected(self, client):
        """Payment reference containing path traversal ('../') must be rejected."""
        uname = "user_traversal_ref"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_live_secretkey123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_12345678/../../charges/ch_1"
            })
            assert resp.status_code in (400, 402)
            data = resp.get_json()
            assert data["ok"] is False

    def test_underpaid_amount_rejected(self, client, monkeypatch):
        """A payment of 1 dollar (100 cents) for a 12,000 DZD plan must be rejected."""
        import db.subscriptions
        uname = "user_underpaid"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        # Mock intent with $1.00 (100 cents)
        intent = {
            "status": "succeeded",
            "amount_received": 100,
            "currency": "dzd",
            "metadata": {"user_id": str(user["id"]), "plan": "pro"}
        }
        monkeypatch.setattr(db.subscriptions, "_fetch_intent", lambda ref, sec: intent, raising=False)

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_live_secretkey123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_underpaid12345"
            })
            assert resp.status_code == 400
            data = resp.get_json()
            assert data["ok"] is False
            assert get_subscription(user["id"])["plan"] == "free"

    def test_intent_missing_metadata_rejected(self, client, monkeypatch):
        """A succeeded payment intent missing user_id/plan in metadata must be rejected."""
        import db.subscriptions
        uname = "user_no_meta"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        intent = {
            "status": "succeeded",
            "amount_received": 1200000,
            "currency": "dzd",
            "metadata": {}  # Missing user_id and plan
        }
        monkeypatch.setattr(db.subscriptions, "_fetch_intent", lambda ref, sec: intent, raising=False)

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_live_secretkey123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_nometadata1234"
            })
            assert resp.status_code == 400
            data = resp.get_json()
            assert data["ok"] is False

    def test_intent_user_id_mismatch_rejected(self, client, monkeypatch):
        """A payment belonging to another user must be rejected."""
        import db.subscriptions
        uname = "user_attacker"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        intent = {
            "status": "succeeded",
            "amount_received": 1200000,
            "currency": "dzd",
            "metadata": {"user_id": "999999", "plan": "pro"}  # Belongs to another user
        }
        monkeypatch.setattr(db.subscriptions, "_fetch_intent", lambda ref, sec: intent, raising=False)

        with patch.dict(os.environ, {"PAYMENT_GATEWAY_SECRET": "sk_live_secretkey123456789"}):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_victimtoken123"
            })
            assert resp.status_code == 400
            data = resp.get_json()
            assert data["ok"] is False

    def test_sk_test_rejected_in_production(self, client):
        """sk_test_ keys must be strictly rejected when FLASK_ENV=production."""
        uname = "user_sk_test_prod"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        with patch.dict(os.environ, {
            "PAYMENT_GATEWAY_SECRET": "sk_test_1234567890abcdef",
            "FLASK_ENV": "production"
        }):
            resp = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "pi_testtoken12345"
            })
            assert resp.status_code in (400, 403)
            data = resp.get_json()
            assert data["ok"] is False

    def test_no_payment_ref_fails_even_in_testing(self, client):
        """Attempting to upgrade without payment_ref must return 402 even if TESTING is True."""
        uname = "user_no_ref_test"
        create_user(uname, "SecurePassword123!", role="analyst")
        user = get_user_by_username(uname)

        with client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        resp = client.post("/api/subscription/upgrade", json={
            "plan": "pro"
        })
        assert resp.status_code == 402
        data = resp.get_json()
        assert data["ok"] is False
