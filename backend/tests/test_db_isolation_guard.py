import os
import sqlite3
import hashlib
import pytest

def get_file_sha256(filepath):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_db_table_counts(filepath):
    if not os.path.exists(filepath):
        return {}
    conn = sqlite3.connect(filepath)
    cur = conn.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    counts = {}
    for t in tables:
        try:
            cnt = cur.execute(f"SELECT count(*) FROM [{t}]").fetchone()[0]
            counts[t] = cnt
        except Exception as e:
            counts[t] = str(e)
    conn.close()
    return counts

def test_production_database_isolation_guard():
    """Guard Test: Asserts that running the test suite NEVER modifies the production database.
    Verifies that the isolated test DB is in use, and production securax.db retains exact row counts.
    """
    # 1. Assert DB_PATH is NOT pointing to production securax.db
    current_db_path = os.environ.get("DB_PATH", "")
    assert "test_session_isolated" in current_db_path or "test_" in current_db_path, (
        f"CRITICAL: DB_PATH '{current_db_path}' is not isolated! Risk of test pollution."
    )
    
    # 2. Assert production securax.db is untouched and phd_dedup_audit has exactly 12 genuine rows
    prod_db = "securax.db"
    if not os.path.exists(prod_db):
        prod_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "securax.db")
    
    if os.path.exists(prod_db):
        counts = get_db_table_counts(prod_db)
        # phd_dedup_audit must remain 12 (not 14)
        assert counts.get("phd_dedup_audit") == 12, (
            f"Isolation violation: phd_dedup_audit has {counts.get('phd_dedup_audit')} rows, expected 12."
        )
        # Users must remain 30
        assert counts.get("users") == 30, (
            f"Isolation violation: users has {counts.get('users')} rows, expected 30."
        )
        # Learning exercises must remain 96
        assert counts.get("learning_exercises") == 96, (
            f"Isolation violation: learning_exercises has {counts.get('learning_exercises')} rows, expected 96."
        )
        # Opportunities must remain 27
        assert counts.get("phd_opportunities") == 27, (
            f"Isolation violation: phd_opportunities has {counts.get('phd_opportunities')} rows, expected 27."
        )
