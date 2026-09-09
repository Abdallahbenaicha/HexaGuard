"""Test suite for Part 5: ARIA Socratic Red-Team Mentor Mode.

Acceptance Criteria:
  1. In mentor_mode=True, ARIA responds with diagnostic/probing questions without raw exploit payloads.
  2. Override trigger phrase (e.g. 'reveal solution', 'اكشف الحل') bypasses mentor restrictions and returns direct solution.
  3. Supports both English and Arabic Socratic guidance.
  4. POST /api/ai/chat honors mentor_mode flag and returns mentor_mode=True in JSON.
  5. Honors monthly quota limits (check_and_consume_ai_quota) and F-03 privacy opt-out.
"""

import os
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, set_user_ai_opt_out
from ai_agent import get_aria


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_aria_mentor.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-aria-mentor")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_aria_mentor_mode_socratic_inquiry_english():
    """In mentor mode, ARIA asks questions instead of handing over copy-paste payloads."""
    aria = get_aria()
    msg = "How do I exploit SQL injection in this login field?"

    # Normal mode contains raw payload or direct fix
    normal_reply = aria.chat(msg, mentor_mode=False, user_id="user_test_en")

    # Mentor mode provides Socratic questions
    mentor_reply = aria.chat(msg, mentor_mode=True, user_id="user_test_en")

    assert "🧠" in mentor_reply or "Mentor" in mentor_reply
    # Socratic reply asks guiding questions
    assert "?" in mentor_reply
    # Raw attack payload should not be present in mentor mode
    assert "' OR 1=1 --" not in mentor_reply


def test_aria_mentor_mode_socratic_inquiry_arabic():
    """In Arabic, ARIA responds with Socratic mentoring in Arabic."""
    aria = get_aria()
    msg = "كيف استغل ثغرة xss في الموقع؟"

    reply = aria.chat(msg, mentor_mode=True, user_id="user_test_ar")
    assert "الموجّه السقراطي" in reply or "🧠" in reply
    assert "؟" in reply
    assert "<script>document.location" not in reply


def test_aria_mentor_override_phrase_reveals_solution():
    """When user supplies the override phrase, direct solution is revealed."""
    aria = get_aria()

    # English override
    override_msg_en = "reveal solution for sql injection"
    reply_en = aria.chat(override_msg_en, mentor_mode=True, user_id="user_override")
    assert "' OR 1=1 --" in reply_en or "SELECT" in reply_en

    # Arabic override
    override_msg_ar = "اكشف الحل لثغرة حقن sql"
    reply_ar = aria.chat(override_msg_ar, mentor_mode=True, user_id="user_override")
    assert "' OR 1=1 --" in reply_ar or "SELECT" in reply_ar or "cursor.execute" in reply_ar


def test_api_chat_mentor_mode_endpoint():
    """POST /api/ai/chat accepts mentor_mode and returns mentor_mode in response."""
    app = create_app()
    client = app.test_client()

    create_user("cadet_mentor", "Password123!", role="analyst", email="cm@example.com")
    user = get_user_by_username("cadet_mentor")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post("/api/ai/chat", json={
        "message": "explain cross-site scripting attack",
        "mentor_mode": True,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("mentor_mode") is True
    reply = data.get("reply", "")
    assert "?" in reply


def test_api_chat_mentor_mode_quota_and_opt_out():
    """Mentor chat respects F-03 data privacy opt-out and monthly quota."""
    app = create_app()
    client = app.test_client()

    create_user("privacy_cadet", "Password123!", role="analyst", email="pc@example.com")
    user = get_user_by_username("privacy_cadet")
    set_user_ai_opt_out(user["id"], True)

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post("/api/ai/chat", json={
        "message": "how does authentication work?",
        "mentor_mode": True,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "messages_used" in data
    # With opt_out=True, provider should fall back safely to offline or local ollama, never crashing
    assert data.get("provider") in ("offline", "ollama")
