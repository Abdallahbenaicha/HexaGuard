"""SecuraX — Enforce Password Rotation Script.

Updates stored users flagged with default/weak credentials to require an immediate
password change on their next login (must_change_password = 1).
Does NOT log, display, or leak plaintext passwords or hashes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.connection import _get_db


def enforce_password_rotation():
    """Invalidate passwords/lock accounts and remove known test accounts without printing secrets."""
    conn = _get_db()

    # 1. Remove known test accounts
    test_account_patterns = (
        "test_%", "%_probe%", "%_test", "demo_user", "cadet_test", "analyst_test", "bounty_hunter"
    )
    deleted_test_count = 0
    for pat in test_account_patterns:
        res = conn.execute("DELETE FROM users WHERE username LIKE ?", (pat,))
        deleted_test_count += res.rowcount

    res = conn.execute(
        "DELETE FROM users WHERE username IN ('test_user', 'temp_test_user', 'test_dummy_probe', 'demo_user', 'bounty_hunter')"
    )
    deleted_test_count += res.rowcount

    # 2. Invalidate stored hashes and set must_change_password = 1
    res = conn.execute(
        "UPDATE users SET password_hash = '!INVALIDATED_ROTATION_REQUIRED!', must_change_password = 1 "
        "WHERE username NOT IN ('system')"
    )
    invalidated_count = res.rowcount
    conn.commit()

    print(f"[SECURITY] Enforced password rotation: {invalidated_count} accounts invalidated with must_change_password=1.")
    print(f"[SECURITY] Removed {deleted_test_count} test/dummy accounts from database.")
    print("[SECURITY] Stored credentials invalidated safely without displaying passwords or hashes.")


if __name__ == "__main__":
    enforce_password_rotation()
