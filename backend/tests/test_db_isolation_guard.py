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
    Verifies that the isolated test DB is in use, and production securax.db is not targeted.
    """
    # 1. Assert DB_PATH is pointing to an isolated temporary test database
    current_db_path = os.environ.get("DB_PATH", "")
    assert "test_session_isolated" in current_db_path or "test_" in current_db_path, (
        f"CRITICAL: DB_PATH '{current_db_path}' is not isolated! Risk of test pollution."
    )
    
    # 2. Assert production securax.db path is strictly distinct from active DB_PATH
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prod_db_paths = [
        os.path.abspath("securax.db"),
        os.path.abspath(os.path.join(backend_dir, "securax.db")),
        os.path.abspath(os.path.join(os.path.dirname(backend_dir), "securax.db")),
    ]
    abs_current = os.path.abspath(current_db_path)
    for p in prod_db_paths:
        assert abs_current != p, f"Isolation violation: Active test DB_PATH matches production path '{p}'"

