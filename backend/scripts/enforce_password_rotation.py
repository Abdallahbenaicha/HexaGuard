"""SecuraX — Enforce Password Rotation Script.

Updates stored users flagged with default/weak credentials to require an immediate
password change on their next login (must_change_password = 1).
Does NOT log, display, or leak plaintext passwords or hashes.

Usage:
    python backend/scripts/enforce_password_rotation.py           # Dry-run mode by default
    python backend/scripts/enforce_password_rotation.py --apply   # Apply rotation (creates .backup first)
"""

import argparse
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
import bcrypt

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.connection import DB_PATH, _resolve_db_path
from forms import check_password_complexity

logger = logging.getLogger(__name__)

# Explicit list of dummy/test accounts to remove - NO SQL LIKE wildcards
EXACT_TEST_USERS = {
    "test_user", "temp_test_user", "test_dummy_probe", "demo_user",
    "bounty_hunter", "audit_probe", "cadet_test", "analyst_test",
    "cadet1", "cadet2", "cadet3", "cadet4", "cadet5",
    "attacker_user", "owner_user", "bounty_tester"
}

KNOWN_WEAK_PASSWORDS = [
    "Password123!", "Admin@2024!", "Analyst@2024!", "Password1!",
    "Welcome2024!", "Summer2024!!", "Abcd1234!@#$", "Qwerty123!",
    "Password@123", "Admin123!", "SecuraX2024!", "SecuraX@2024!",
    "12345678", "password", "admin", "admin123", "letmein", "changeme"
]


def load_weak_passwords(max_common: int = 50) -> list[str]:
    """Load curated weak and default passwords for efficient bcrypt verification."""
    seen = set(KNOWN_WEAK_PASSWORDS)
    passwords = list(KNOWN_WEAK_PASSWORDS)
    dict_path = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"
    if dict_path.exists():
        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                count = 0
                for line in f:
                    w = line.strip()
                    if w and w not in seen:
                        seen.add(w)
                        passwords.append(w)
                        count += 1
                        if count >= max_common:
                            break
        except Exception as exc:
            logger.warning("Could not read common_passwords.txt: %s", exc)
    return passwords


def is_hash_weak(password_hash: str, weak_passwords: list[str]) -> bool:
    """Check if stored bcrypt hash matches any known weak password."""
    if not password_hash or password_hash.startswith("!INVALIDATED"):
        return False
    try:
        h_bytes = password_hash.encode("utf-8")
        for weak in weak_passwords:
            if bcrypt.checkpw(weak.encode("utf-8"), h_bytes):
                return True
    except Exception:
        pass
    return False


def enforce_password_rotation(apply: bool = False, db_path: str = None) -> dict:
    """Invalidate passwords/lock accounts and remove known test accounts without printing secrets."""
    resolved_path = _resolve_db_path(db_path or os.environ.get("DB_PATH") or "securax.db")
    if not os.path.exists(resolved_path):
        print(f"[!] Database file not found at: {resolved_path}")
        return {"deleted_test_accounts": 0, "invalidated_accounts": 0, "preserved_accounts": 0}

    conn = sqlite3.connect(resolved_path)
    conn.row_factory = sqlite3.Row

    # Fetch all existing users
    users = conn.execute("SELECT id, username, password_hash, role, is_active FROM users").fetchall()

    test_users_to_delete = []
    users_to_invalidate = []
    users_preserved = []

    weak_passwords = load_weak_passwords()
    admin_env_pw = os.environ.get("SECURAX_ADMIN_PASSWORD", "").strip()
    analyst_env_pw = os.environ.get("SECURAX_ANALYST_PASSWORD", "").strip()

    for u in users:
        uname = u["username"]
        pwh = u["password_hash"]

        # 1. Check exact test user deletion
        if uname in EXACT_TEST_USERS:
            test_users_to_delete.append(uname)
            continue

        # 2. Never touch system user
        if uname == "system":
            users_preserved.append(uname)
            continue

        # 3. Check admin/analyst with environment variables
        if uname == "admin" and admin_env_pw:
            users_preserved.append(uname)
            continue
        if uname == "analyst" and analyst_env_pw:
            users_preserved.append(uname)
            continue

        # 4. Check if user hash matches any weak password
        if is_hash_weak(pwh, weak_passwords):
            users_to_invalidate.append(uname)
        else:
            users_preserved.append(uname)

    print("=" * 60)
    print("SecuraX Credential Rotation & Sanitization Plan")
    print(f"Mode: {'APPLY (Changes will be written)' if apply else 'DRY-RUN (Simulating only)'}")
    print(f"Database: {resolved_path}")
    print("=" * 60)
    print(f"Found {len(test_users_to_delete)} exact test/dummy accounts to remove.")
    print(f"Found {len(users_to_invalidate)} accounts with weak/default credentials to invalidate.")
    print(f"Preserved {len(users_preserved)} legitimate accounts with strong/custom credentials.")

    if not apply:
        print("\n[INFO] Dry-run completed. No database changes were made.")
        print("[INFO] Run with '--apply' to execute these changes after reviewing.")
        conn.close()
        return {
            "deleted_test_accounts": len(test_users_to_delete),
            "invalidated_accounts": len(users_to_invalidate),
            "preserved_accounts": len(users_preserved),
        }

    # Backup before applying changes
    backup_file = f"{resolved_path}.pre_rotation_{int(time.time())}.bak"
    try:
        with sqlite3.connect(backup_file) as bck:
            conn.backup(bck)
        print(f"[BACKUP] Created database backup at: {backup_file}")
    except Exception as exc:
        print(f"[ERROR] Failed to create database backup: {exc}")
        conn.close()
        raise

    # 1. Delete exact test accounts
    for uname in test_users_to_delete:
        conn.execute("DELETE FROM users WHERE username = ?", (uname,))

    # 2. Invalidate weak account credentials
    for uname in users_to_invalidate:
        conn.execute(
            "UPDATE users SET password_hash = '!INVALIDATED_ROTATION_REQUIRED!', must_change_password = 1 "
            "WHERE username = ?",
            (uname,)
        )

    # 3. If admin/analyst passwords are set in environment, re-hash them
    if admin_env_pw:
        admin_hash = bcrypt.hashpw(admin_env_pw.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0, is_active = 1 WHERE username = 'admin'",
            (admin_hash,)
        )
    if analyst_env_pw:
        analyst_hash = bcrypt.hashpw(analyst_env_pw.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0, is_active = 1 WHERE username = 'analyst'",
            (analyst_hash,)
        )

    conn.commit()
    conn.close()

    print("[SUCCESS] Applied credential rotation successfully.")
    print(f"[SECURITY] Removed {len(test_users_to_delete)} test accounts.")
    print(f"[SECURITY] Flagged {len(users_to_invalidate)} accounts with must_change_password=1.")
    print("[SECURITY] Passwords and hashes were handled securely without console logging.")

    return {
        "deleted_test_accounts": len(test_users_to_delete),
        "invalidated_accounts": len(users_to_invalidate),
        "preserved_accounts": len(users_preserved),
    }


def main():
    parser = argparse.ArgumentParser(description="Enforce password rotation and delete exact test accounts.")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    parser.add_argument("--dry-run", action="store_true", help="Run without modifying database (default)")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    args = parser.parse_args()

    apply = args.apply and not args.dry_run
    enforce_password_rotation(apply=apply, db_path=args.db)


if __name__ == "__main__":
    main()
