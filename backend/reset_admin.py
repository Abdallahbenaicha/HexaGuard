"""Run this script to reset the admin (and optionally analyst) password.
Works locally and on Render/HuggingFace shells.

    python reset_admin.py
"""

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path
import bcrypt

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.connection import DB_PATH, _resolve_db_path
from forms import check_password_complexity


def reset_password(username: str, new_password: str, conn: sqlite3.Connection) -> bool:
    pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    cur = conn.execute(
        "UPDATE users SET password_hash=?, must_change_password=0, is_active=1 WHERE username=?",
        (pw_hash, username),
    )
    conn.commit()
    return cur.rowcount > 0


def create_admin_if_missing(username: str, password: str, role: str, conn: sqlite3.Connection):
    import json
    from datetime import datetime, timezone
    exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        return False
    perms = (
        json.dumps(["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"])
        if role == "admin"
        else json.dumps(["run_scan", "view_reports"])
    )
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by,must_change_password)"
        " VALUES (?,?,?,?,1,?,?,0)",
        (username, pw_hash, role, perms, now, "reset_script"),
    )
    conn.commit()
    return True


def main():
    resolved_db_path = _resolve_db_path(DB_PATH or "securax.db")
    parser = argparse.ArgumentParser(description="Reset SecuraX admin/analyst passwords securely")
    parser.add_argument("--admin-password", default=None, help="New admin password (if omitted, prompts securely via getpass)")
    parser.add_argument("--analyst-password", default=None, help="New analyst password (if omitted, prompts securely via getpass)")
    parser.add_argument("--db", default=resolved_db_path, help="Path to SQLite DB")
    args = parser.parse_args()

    db_path = _resolve_db_path(args.db)
    if not Path(db_path).exists():
        print(f"[!] Database not found at: {db_path}")
        print("    Make sure the Flask app has been started at least once to create the DB.")
        sys.exit(1)

    admin_pw = args.admin_password or os.environ.get("SECURAX_ADMIN_PASSWORD")
    if not admin_pw:
        try:
            admin_pw = getpass.getpass("Enter new password for 'admin': ")
            conf = getpass.getpass("Confirm new password for 'admin': ")
            if admin_pw != conf:
                print("[!] Passwords do not match.")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted.")
            sys.exit(1)

    is_valid, reason = check_password_complexity(admin_pw, username="admin")
    if not is_valid:
        print(f"[!] Admin password does not meet security requirements: {reason}")
        sys.exit(1)

    analyst_pw = args.analyst_password or os.environ.get("SECURAX_ANALYST_PASSWORD")

    conn = sqlite3.connect(db_path)

    for username, password, role in [
        ("admin", admin_pw, "admin"),
        ("analyst", analyst_pw, "analyst"),
    ]:
        if not password:
            continue
        created = create_admin_if_missing(username, password, role, conn)
        if created:
            print(f"[+] Created missing user '{username}' with role '{role}'")
        else:
            ok = reset_password(username, password, conn)
            status = "OK" if ok else "NOT FOUND"
            print(f"[{'OK' if ok else '!'}] Reset password for '{username}': {status}")

    conn.close()
    print("\n[SUCCESS] Credentials updated securely. Password plaintext is never stored or echoed.")


if __name__ == "__main__":
    main()
