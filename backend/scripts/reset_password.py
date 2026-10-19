"""SecuraX — Admin/User Password Reset Utility.

Safely resets a user's password without leaking credentials or storing them in shell history.
Prompts for password securely via getpass and enforces standard password complexity rules.

Usage:
    python backend/scripts/reset_password.py <username>
    python backend/scripts/reset_password.py <username> --db /path/to/securax.db
"""

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path
import bcrypt

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.connection import DB_PATH, _resolve_db_path
from forms import check_password_complexity


def reset_user_password(username: str, db_path: str = None, new_password: str = None) -> bool:
    """Reset password for specified user, checking complexity and updating securely."""
    resolved_path = _resolve_db_path(db_path or os.environ.get("DB_PATH") or "securax.db")
    if not os.path.exists(resolved_path):
        print(f"[!] Database file not found at: {resolved_path}")
        return False

    conn = sqlite3.connect(resolved_path)
    conn.row_factory = sqlite3.Row

    user = conn.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        print(f"[!] User '{username}' does not exist in database.")
        conn.close()
        return False

    if new_password is None:
        try:
            pw1 = getpass.getpass(f"Enter new password for '{username}': ")
            pw2 = getpass.getpass("Confirm new password: ")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Password reset aborted.")
            conn.close()
            return False

        if pw1 != pw2:
            print("[!] Passwords do not match.")
            conn.close()
            return False
        new_password = pw1

    # Check complexity
    is_valid, reason = check_password_complexity(new_password, username=username)
    if not is_valid:
        print(f"[!] Password does not meet security requirements: {reason}")
        conn.close()
        return False

    pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0, is_active = 1 WHERE username = ?",
        (pw_hash, username)
    )
    conn.commit()
    conn.close()

    print(f"[SUCCESS] Password for '{username}' was securely updated.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Reset password for any user safely using getpass.")
    parser.add_argument("username", help="Username of the account to reset")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database")
    args = parser.parse_args()

    ok = reset_user_password(username=args.username, db_path=args.db)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
