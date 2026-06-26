"""Tests for database CRUD operations (uses in-memory SQLite)."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets a fresh in-memory SQLite database."""
    db_file = str(tmp_path / "test.db")
    monkeypatch.setenv("DB_PATH", db_file)
    # Reset thread-local connection
    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file
    db.init_db()
    yield
    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestCreateUser:
    def test_create_basic_user(self):
        ok, msg = db.create_user("alice", "Password1!", role="analyst")
        assert ok
        assert "created" in msg.lower()

    def test_duplicate_username_rejected(self):
        db.create_user("bob", "Password1!")
        ok, msg = db.create_user("bob", "OtherPass1!")
        assert not ok
        assert "exists" in msg.lower()

    def test_user_role_stored_correctly(self):
        db.create_user("charlie", "Password1!", role="admin")
        user = db.get_user_by_username("charlie")
        assert user["role"] == "admin"

    def test_permissions_stored_as_list(self):
        db.create_user("diana", "Password1!", permissions=["run_scan"])
        user = db.get_user_by_username("diana")
        assert isinstance(user["permissions"], list)
        assert "run_scan" in user["permissions"]


class TestGetUser:
    def test_get_by_username(self):
        db.create_user("eve", "Password1!")
        user = db.get_user_by_username("eve")
        assert user is not None
        assert user["username"] == "eve"

    def test_nonexistent_user_returns_none(self):
        assert db.get_user_by_username("ghost") is None

    def test_get_by_id(self):
        db.create_user("frank", "Password1!")
        user = db.get_user_by_username("frank")
        fetched = db.get_user_by_id(user["id"])
        assert fetched["username"] == "frank"


class TestUpdateUser:
    def test_change_role(self):
        db.create_user("grace", "Password1!", role="analyst")
        user = db.get_user_by_username("grace")
        db.update_user(user["id"], role="admin")
        updated = db.get_user_by_id(user["id"])
        assert updated["role"] == "admin"

    def test_deactivate_user(self):
        db.create_user("henry", "Password1!")
        user = db.get_user_by_username("henry")
        db.update_user(user["id"], is_active=0)
        updated = db.get_user_by_id(user["id"])
        assert updated["is_active"] == 0

    def test_password_change(self):
        db.create_user("ivan", "OldPass1!")
        user = db.get_user_by_username("ivan")
        db.update_user(user["id"], new_password="NewPass2!")
        updated = db.get_user_by_id(user["id"])
        assert updated["password_hash"] != user["password_hash"]


class TestAuditLog:
    def test_log_event_created(self):
        db.log_event("login_success", username="tester", user_id=1, category="auth")
        logs, total = db.get_audit_log(category="auth", limit=10)
        assert total >= 1
        assert any(e["action"] == "login_success" for e in logs)

    def test_log_event_filters_by_category(self):
        db.log_event("scan_complete", username="tester", user_id=1, category="scan")
        db.log_event("login_failed", username="tester", user_id=1, category="auth")
        logs, _ = db.get_audit_log(category="scan", limit=10)
        assert all(e["category"] == "scan" for e in logs)


class TestReports:
    def test_store_and_retrieve_report(self):
        db.create_user("julia", "Password1!")
        user = db.get_user_by_username("julia")
        result = {
            "scan_type": "web",
            "target": "example.com",
            "vulnerabilities": [{"severity": "high", "check": "xss", "title": "XSS", "description": ""}],
        }
        token = db.store_report(result, risk_score=7.5, original_content=None,
                                user_id=user["id"], username="julia")
        assert len(token) == 32  # uuid4().hex
        report = db.get_report(token)
        assert report is not None
        assert report["scan_type"] == "web"

    def test_delete_report(self):
        db.create_user("kevin", "Password1!")
        user = db.get_user_by_username("kevin")
        result = {"scan_type": "ssl", "target": "test.com", "vulnerabilities": []}
        token = db.store_report(result, 0.0, None, user["id"], "kevin")
        db.delete_report(token)
        assert db.get_report(token) is None

    def test_user_reports_list(self):
        db.create_user("laura", "Password1!")
        user = db.get_user_by_username("laura")
        for i in range(3):
            db.store_report(
                {"scan_type": "web", "target": f"site{i}.com", "vulnerabilities": []},
                float(i), None, user["id"], "laura",
            )
        reports = db.get_user_reports(user["id"])
        assert len(reports) == 3


class TestScheduledScans:
    def test_create_and_list(self):
        db.create_user("mike", "Password1!")
        user = db.get_user_by_username("mike")
        sched_id = db.create_scheduled_scan(user["id"], "mike", "web", "example.com", "daily")
        assert sched_id > 0
        scans = db.get_user_scheduled_scans(user["id"])
        assert len(scans) == 1
        assert scans[0]["scan_type"] == "web"

    def test_toggle_active(self):
        db.create_user("nina", "Password1!")
        user = db.get_user_by_username("nina")
        sched_id = db.create_scheduled_scan(user["id"], "nina", "ssl", "site.com")
        db.toggle_scheduled_scan(sched_id, user["id"], False)
        scans = db.get_user_scheduled_scans(user["id"])
        assert scans[0]["is_active"] == 0

    def test_delete_scheduled(self):
        db.create_user("oscar", "Password1!")
        user = db.get_user_by_username("oscar")
        sched_id = db.create_scheduled_scan(user["id"], "oscar", "network", "192.168.1.1")
        ok = db.delete_scheduled_scan(sched_id, user["id"])
        assert ok
        assert db.get_user_scheduled_scans(user["id"]) == []
