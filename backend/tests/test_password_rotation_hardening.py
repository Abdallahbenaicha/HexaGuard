"""Tests for Enforce Password Rotation Hardening & Recovery CLI (fix/round4 item 2)."""

import os
import sqlite3
import pytest
import bcrypt
from unittest.mock import patch

from db.connection import init_db
from scripts.enforce_password_rotation import enforce_password_rotation, EXACT_TEST_USERS


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_rotation.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("SECURAX_ADMIN_PASSWORD", "SuperSecureAdminPass2026!")
    monkeypatch.setenv("SECURAX_ANALYST_PASSWORD", "SuperSecureAnalystPass2026!")

    # Initialize schema
    init_db()

    conn = sqlite3.connect(db_file)
    # Seed specific accounts: tester, latest, bob_probe_fan, alice, weak_user, admin
    # "tester", "latest", "bob_probe_fan" have regular passwords and MUST NOT be deleted by LIKE wildcards
    # "weak_user" has "Password123!" and MUST be flagged/locked
    # "alice" has a strong custom password and MUST NOT be locked
    pw_strong = bcrypt.hashpw(b"SuperUniquePass789!#", bcrypt.gensalt(4)).decode()
    pw_weak = bcrypt.hashpw(b"Password123!", bcrypt.gensalt(4)).decode()

    users_to_seed = [
        ("tester", pw_strong, "analyst"),
        ("latest", pw_strong, "analyst"),
        ("bob_probe_fan", pw_strong, "analyst"),
        ("alice", pw_strong, "analyst"),
        ("weak_user", pw_weak, "analyst"),
        ("test_user", pw_weak, "analyst"),       # Known exact test user -> to delete
        ("audit_probe", pw_weak, "analyst"),     # Known exact test user -> to delete
    ]

    for uname, pwh, role in users_to_seed:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash, role, permissions, is_active, created_at, created_by, must_change_password)"
            " VALUES (?, ?, ?, '[]', 1, '2026-01-01T00:00:00Z', 'seed', 0)",
            (uname, pwh, role)
        )
    conn.commit()
    conn.close()

    return db_file


class TestPasswordRotationHardening:
    def test_dry_run_does_not_modify_database(self, test_db):
        """Default dry-run mode must report findings without mutating any database records."""
        summary = enforce_password_rotation(apply=False, db_path=test_db)

        conn = sqlite3.connect(test_db)
        # Verify no users were deleted
        rows = {r[0] for r in conn.execute("SELECT username FROM users").fetchall()}
        assert "tester" in rows
        assert "latest" in rows
        assert "bob_probe_fan" in rows
        assert "test_user" in rows  # not deleted in dry-run

        # Verify weak_user hash was not modified
        weak_hash = conn.execute("SELECT password_hash FROM users WHERE username = 'weak_user'").fetchone()[0]
        assert weak_hash.startswith("$2b$")
        conn.close()

    def test_apply_removes_only_exact_test_accounts_and_locks_only_weak(self, test_db, monkeypatch):
        """When --apply is run:
        - tester, latest, bob_probe_fan, alice are preserved.
        - only EXACT_TEST_USERS (test_user, audit_probe) are removed.
        - only weak_user (matching weak password list) is invalidated/locked.
        - alice (strong password) is untouched.
        - admin password from environment works upon bootstrap.
        """
        summary = enforce_password_rotation(apply=True, db_path=test_db)

        conn = sqlite3.connect(test_db)
        remaining_users = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT username, password_hash, must_change_password FROM users").fetchall()}
        conn.close()

        # 1. Names containing 'test' or 'probe' like tester, latest, bob_probe_fan must NOT be deleted
        assert "tester" in remaining_users
        assert "latest" in remaining_users
        assert "bob_probe_fan" in remaining_users
        assert "alice" in remaining_users

        # 2. Exact test accounts must be deleted
        assert "test_user" not in remaining_users
        assert "audit_probe" not in remaining_users

        # 3. Only weak_user must be locked/must_change_password
        weak_hash, weak_mcp = remaining_users["weak_user"]
        assert weak_mcp == 1 or weak_hash.startswith("!INVALIDATED")

        # 4. Alice must NOT have been locked
        alice_hash, alice_mcp = remaining_users["alice"]
        assert alice_mcp == 0
        assert alice_hash.startswith("$2b$")

    def test_admin_rehashed_from_environment_on_boot(self, test_db, monkeypatch):
        """When SECURAX_ADMIN_PASSWORD is set, booting or initializing DB ensures admin has valid hash."""
        from db.connection import _bootstrap_admin, _get_db
        from db.users import get_user_by_username

        # Invalidate admin hash in database first
        conn = sqlite3.connect(test_db)
        conn.execute("UPDATE users SET password_hash = '!INVALIDATED!', must_change_password = 1 WHERE username = 'admin'")
        conn.commit()
        conn.close()

        # Re-run _bootstrap_admin
        _bootstrap_admin()

        # Admin must now have a valid hash matching SECURAX_ADMIN_PASSWORD
        admin = get_user_by_username("admin")
        assert admin is not None
        assert admin["password_hash"].startswith("$2b$")
        assert bcrypt.checkpw("SuperSecureAdminPass2026!".encode(), admin["password_hash"].encode())
        assert admin["must_change_password"] == 0

    def test_reset_user_password_cli_function(self, test_db):
        """CLI recovery function reset_user_password securely resets any user password."""
        from scripts.reset_password import reset_user_password
        from db.users import get_user_by_username

        # Reset password for weak_user
        new_pass = "CompletelyNewSecurePass2026!#"
        ok = reset_user_password("weak_user", db_path=test_db, new_password=new_pass)
        assert ok is True

        user = get_user_by_username("weak_user")
        assert user is not None
        assert bcrypt.checkpw(new_pass.encode(), user["password_hash"].encode())
        assert user["must_change_password"] == 0
        assert user["is_active"] == 1
