"""F-03 Tests: AI monthly quota tracking and ai_data_sharing_opt_out restriction."""
import os
import sys
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-f03-testing")

import database as db
from ai_agent import ARIA


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_f03.db")
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
        db.create_user("ai_user", "TestPass123!", role="analyst")
        db.create_user("ai_admin", "TestPass123!", role="admin")
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestAIQuotaAndOptOut:
    def test_ai_settings_endpoint_and_toggle(self, app):
        """F-03: User can view and toggle ai_data_sharing_opt_out."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "ai_user", "password": "TestPass123!"})

        # Check default settings (opt_out = False)
        res = client.get("/api/user/ai-settings")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("opt_out") is False
        assert data.get("messages_used") == 0
        assert data.get("max_messages") == 20  # Free plan default

        # Toggle opt_out to True
        res_toggle = client.patch("/api/user/ai-settings", json={"opt_out": True})
        assert res_toggle.status_code == 200
        assert res_toggle.get_json().get("opt_out") is True

        # Verify persisted in database
        res_verify = client.get("/api/user/ai-settings")
        assert res_verify.get_json().get("opt_out") is True

    def test_ai_opt_out_strictly_blocks_external_cloud_calls(self, app):
        """F-03: When opt_out is True, ARIA._ai_call NEVER calls _gemini."""
        user = db.get_user_by_username("ai_user")
        db.set_user_ai_opt_out(user["id"], True)

        aria = ARIA()
        aria.provider = "gemini"

        with patch.object(aria, "_gemini") as mock_gemini, \
             patch.object(aria, "_ollama", return_value="local ollama reply") as mock_ollama:
            # Call _ai_call with user_id that opted out
            reply = aria._ai_call("Analyze this SQLi", user_id=user["id"])
            mock_gemini.assert_not_called()

    def test_ai_chat_quota_enforcement(self, app):
        """F-03: Regular user cannot exceed their monthly AI quota; returns 429 when exhausted."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "ai_user", "password": "TestPass123!"})
        user = db.get_user_by_username("ai_user")

        # Free tier has 20 messages limit. Simulate user has reached 20 used.
        db._exec("UPDATE users SET ai_messages_used=20 WHERE id=?", (user["id"],))

        res = client.post("/api/ai/chat", json={"message": "Hello ARIA"})
        assert res.status_code == 429
        data = res.get_json()
        assert data.get("quota_exceeded") is True
        assert "quota reached" in data.get("error", "").lower()

    def test_admin_is_exempt_from_ai_quota(self, app):
        """F-03: Admin users have unlimited AI quota."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "ai_admin", "password": "TestPass123!"})
        admin_user = db.get_user_by_username("ai_admin")

        db._exec("UPDATE users SET ai_messages_used=9999 WHERE id=?", (admin_user["id"],))

        with patch("ai_agent.ARIA.chat", return_value="Admin reply"):
            res = client.post("/api/ai/chat", json={"message": "Hello ARIA from admin"})
            assert res.status_code == 200
            assert res.get_json().get("reply") == "Admin reply"
