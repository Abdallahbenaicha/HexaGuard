"""Tests for Password Complexity and Rotation Policy (fix/round3 item 3)."""

import os
import io
import sys
import pytest
from forms import check_password_complexity
from db.users import create_user, get_user_by_username
from db.connection import _get_db
from scripts.enforce_password_rotation import enforce_password_rotation


REJECTED_PASSWORDS = [
    "Welcome2024!",
    "Summer2024!!",
    "Abcd1234!@#$",
    "Password1!",
    "Short1!Aa",
    "qwerty123456!A",
    "Admin1234567!@",
]


class TestPasswordPolicy:
    @pytest.mark.parametrize("pwd", REJECTED_PASSWORDS)
    def test_insecure_passwords_rejected(self, pwd):
        ok, msg = check_password_complexity(pwd)
        assert ok is False, f"Password '{pwd}' should have been rejected but was accepted."
        assert len(msg) > 0

    def test_username_in_password_rejected(self):
        ok, msg = check_password_complexity("SuperAlice1234!#", username="alice")
        assert ok is False
        assert "اسم المستخدم" in msg or "username" in msg.lower()

    def test_valid_strong_password_accepted(self):
        ok, msg = check_password_complexity("Xk9#mP2$vL8!zR5@")
        assert ok is True
        assert msg == ""

    def test_enforce_password_rotation_invalidates_hash_and_removes_test_accounts(self):
        # Create test users
        conn = _get_db()
        create_user("test_dummy_probe", "StrongPass123!@#", role="analyst")
        create_user("real_staff_member", "StrongPass123!@#", role="analyst")

        # Capture output to ensure no hashes or passwords are printed
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            enforce_password_rotation()
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        # Ensure no plaintext passwords or bcrypt hashes leaked in output
        assert "$2b$" not in output
        assert "StrongPass" not in output

        # Verify test account was removed
        test_u = get_user_by_username("test_dummy_probe")
        assert test_u is None

        # Verify staff member hash is invalidated and must_change_password=1
        staff = get_user_by_username("real_staff_member")
        assert staff is not None
        assert staff["must_change_password"] == 1
        assert "!INVALIDATED" in staff["password_hash"] or "!LOCKED" in staff["password_hash"]
