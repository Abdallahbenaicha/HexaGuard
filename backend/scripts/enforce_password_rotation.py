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
    """Flag all seeded and legacy users to require password change upon next login."""
    conn = _get_db()

    # Find total users
    cur = conn.execute("SELECT id, username FROM users")
    users = cur.fetchall()
    total = len(users)

    # Set must_change_password = 1 for all accounts except system admin accounts with active random passwords
    # To be secure, flag all seeded accounts like admin_le, cloud_admin, cadet, etc.
    res = conn.execute(
        "UPDATE users SET must_change_password = 1 WHERE username NOT IN ('system')"
    )
    conn.commit()
    updated_count = res.rowcount

    print(f"[SECURITY] Enforced password rotation: {updated_count} of {total} accounts set to must_change_password=1.")
    print("[SECURITY] Passwords must be changed upon next authentication according to strict complexity policy.")


if __name__ == "__main__":
    enforce_password_rotation()
