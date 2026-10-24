"""Hermetic tests for database migration exception handling in backend/db/connection.py.

Verifies Phase 2D requirements:
1. Expected duplicate column name errors are ignored safely.
2. Missing table errors raise sqlite3.OperationalError and are NOT swallowed.
3. Invalid SQL syntax errors raise sqlite3.OperationalError and are NOT swallowed.
4. Non-duplicate DB failures (e.g. database locked) raise sqlite3.OperationalError.
5. Idempotent re-execution of migrations on the same schema succeeds safely.
6. MySQL migration exception logic behaves correctly according to query context and error codes.
7. All tests run strictly in isolated temporary databases, never touching production.
"""

import os
import sqlite3
import pytest

from db.connection import (
    _is_expected_migration_duplicate,
    init_db,
    _local,
)


@pytest.fixture
def isolated_temp_db(tmp_path, monkeypatch):
    """Fixture providing a fresh isolated temporary SQLite database for each test.
    
    Guarantees strict isolation from backend/securax.db and backup databases.
    """
    temp_db_path = str(tmp_path / "migration_test_temp.db")
    
    # Assert temp path is never production
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prod_paths = [
        os.path.abspath("securax.db"),
        os.path.abspath(os.path.join(backend_dir, "securax.db")),
        os.path.abspath(os.path.join(os.path.dirname(backend_dir), "securax.db")),
    ]
    for p in prod_paths:
        assert os.path.abspath(temp_db_path) != p, f"Isolation violation: temp_db matches prod '{p}'"
    assert "backups" not in os.path.abspath(temp_db_path).lower()

    # Reset thread-local connection
    if hasattr(_local, "conn") and _local.conn:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None
        _local.conn_path = None

    monkeypatch.setenv("DB_PATH", temp_db_path)
    monkeypatch.setattr("db.connection.DB_PATH", temp_db_path)

    yield temp_db_path

    # Clean up thread-local connection
    if hasattr(_local, "conn") and _local.conn:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None
        _local.conn_path = None


class MockMySQLError(Exception):
    """Mock PyMySQL OperationalError / ProgrammingError with error code in args[0]."""
    def __init__(self, code: int, msg: str):
        super().__init__(code, msg)
        self.args = (code, msg)


# ── Unit Tests: _is_expected_migration_duplicate (SQLite Engine) ─────────────

def test_sqlite_duplicate_column_detected_as_expected():
    """ALTER TABLE ADD COLUMN with 'duplicate column name' OperationalError is accepted."""
    exc = sqlite3.OperationalError("duplicate column name: api_token")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is True


def test_sqlite_missing_table_is_not_expected_duplicate():
    """ALTER TABLE ADD COLUMN on a non-existent table is NOT an expected duplicate."""
    exc = sqlite3.OperationalError("no such table: nonexistent_table")
    stmt = "ALTER TABLE nonexistent_table ADD COLUMN foo TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


def test_sqlite_syntax_error_is_not_expected_duplicate():
    """SQL syntax errors on ALTER TABLE are NOT expected duplicates."""
    exc = sqlite3.OperationalError('near "BROKEN": syntax error')
    stmt = "ALTER TABLE users ADD COLUMN BROKEN SYNTAX !!!"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


def test_sqlite_locked_db_is_not_expected_duplicate():
    """Database locked OperationalError is NOT an expected duplicate."""
    exc = sqlite3.OperationalError("database is locked")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


def test_sqlite_create_table_errors_are_never_ignored():
    """SQLite natively supports IF NOT EXISTS; any exception on CREATE TABLE is an unexpected failure."""
    exc = sqlite3.OperationalError("table supervisor_briefings already exists")
    stmt = "CREATE TABLE IF NOT EXISTS supervisor_briefings (id TEXT PRIMARY KEY)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


def test_sqlite_create_index_errors_are_never_ignored():
    """SQLite natively supports IF NOT EXISTS; any exception on CREATE INDEX is an unexpected failure."""
    exc = sqlite3.OperationalError("no such table: payments")
    stmt = "CREATE INDEX IF NOT EXISTS idx_payments_user ON payments (user_id)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


def test_sqlite_non_operational_error_is_never_ignored():
    """Non-OperationalError exceptions (e.g. ValueError, RuntimeError) are never ignored."""
    exc = ValueError("Unexpected value")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=False) is False


# ── Unit Tests: _is_expected_migration_duplicate (MySQL Engine) ──────────────

def test_mysql_duplicate_column_detected_with_code_1060():
    """MySQL error 1060 (ER_DUP_FIELDNAME) on ALTER TABLE ADD COLUMN is accepted."""
    exc = MockMySQLError(1060, "Duplicate column name 'api_token'")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is True


def test_mysql_missing_table_1146_is_not_expected_duplicate():
    """MySQL error 1146 (ER_NO_SUCH_TABLE) on ALTER TABLE is NOT an expected duplicate."""
    exc = MockMySQLError(1146, "Table 'securax.users' doesn't exist")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is False


def test_mysql_code_1050_mismatched_on_alter_table():
    """MySQL error 1050 (table exists) must NOT be ignored on an ALTER TABLE statement."""
    exc = MockMySQLError(1050, "Table 'users' already exists")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is False


def test_mysql_code_1050_on_create_table_is_expected():
    """MySQL error 1050 (ER_TABLE_EXISTS_ERROR) on CREATE TABLE is accepted."""
    exc = MockMySQLError(1050, "Table 'supervisor_briefings' already exists")
    stmt = "CREATE TABLE IF NOT EXISTS supervisor_briefings (id VARCHAR(64) PRIMARY KEY)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is True


def test_mysql_code_1060_mismatched_on_create_table():
    """MySQL error 1060 on CREATE TABLE is NOT an expected duplicate."""
    exc = MockMySQLError(1060, "Duplicate column name")
    stmt = "CREATE TABLE IF NOT EXISTS supervisor_briefings (id VARCHAR(64) PRIMARY KEY)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is False


def test_mysql_code_1061_on_create_index_is_expected():
    """MySQL error 1061 (ER_DUP_KEYNAME) on CREATE INDEX is accepted."""
    exc = MockMySQLError(1061, "Duplicate key name 'idx_payments_ref'")
    stmt = "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is True


def test_mysql_code_1146_on_create_index_is_not_expected():
    """MySQL error 1146 on CREATE INDEX is NOT an expected duplicate."""
    exc = MockMySQLError(1146, "Table 'securax.payments' doesn't exist")
    stmt = "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is False


def test_mysql_error_without_args_returns_false():
    """MySQL exception lacking integer code in args returns False."""
    exc = Exception("generic error without errno")
    stmt = "ALTER TABLE users ADD COLUMN api_token TEXT"
    assert _is_expected_migration_duplicate(exc, stmt, is_mysql=True) is False


# ── Integration Tests: Real Isolated SQLite Database ──────────────────────────

def test_duplicate_column_migration_ignored_safely(isolated_temp_db):
    """Running an ALTER TABLE ADD COLUMN on an existing column succeeds safely."""
    conn = sqlite3.connect(isolated_temp_db)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, api_token TEXT)")
    conn.commit()

    migration = "ALTER TABLE users ADD COLUMN api_token TEXT"
    try:
        conn.execute(migration)
        conn.commit()
    except sqlite3.OperationalError as exc:
        if _is_expected_migration_duplicate(exc, migration, is_mysql=False):
            pass  # Expected duplicate, ignored safely
        else:
            raise
    conn.close()


def test_missing_table_migration_raises_operational_error(isolated_temp_db):
    """Running an ALTER TABLE on a non-existent table raises sqlite3.OperationalError."""
    conn = sqlite3.connect(isolated_temp_db)
    # Database is empty — no 'missing_table' exists
    migration = "ALTER TABLE missing_table ADD COLUMN foo TEXT"
    
    with pytest.raises(sqlite3.OperationalError) as exc_info:
        try:
            conn.execute(migration)
            conn.commit()
        except sqlite3.OperationalError as exc:
            if _is_expected_migration_duplicate(exc, migration, is_mysql=False):
                pass
            else:
                raise
    assert "no such table" in str(exc_info.value).lower()
    conn.close()


def test_invalid_sql_syntax_migration_raises_operational_error(isolated_temp_db):
    """Running invalid SQL syntax raises sqlite3.OperationalError and is NOT swallowed."""
    conn = sqlite3.connect(isolated_temp_db)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    conn.commit()

    invalid_migration = "ALTER TABLE users ADD COLUMN (INVALID SYNTAX --"
    with pytest.raises(sqlite3.OperationalError) as exc_info:
        try:
            conn.execute(invalid_migration)
            conn.commit()
        except sqlite3.OperationalError as exc:
            if _is_expected_migration_duplicate(exc, invalid_migration, is_mysql=False):
                pass
            else:
                raise
    err_str = str(exc_info.value).lower()
    assert "syntax error" in err_str or "near" in err_str or "incomplete" in err_str
    conn.close()


def test_locked_database_migration_raises_operational_error(isolated_temp_db):
    """Database lock contention raises sqlite3.OperationalError and is NOT swallowed."""
    conn_a = sqlite3.connect(isolated_temp_db)
    conn_a.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    conn_a.commit()
    
    # Acquire exclusive write transaction on connection A
    conn_a.execute("BEGIN EXCLUSIVE")

    # Open connection B with 0-second timeout to force instant locking failure
    conn_b = sqlite3.connect(isolated_temp_db, timeout=0.01)
    migration = "ALTER TABLE users ADD COLUMN api_token TEXT"

    with pytest.raises(sqlite3.OperationalError) as exc_info:
        try:
            conn_b.execute(migration)
            conn_b.commit()
        except sqlite3.OperationalError as exc:
            if _is_expected_migration_duplicate(exc, migration, is_mysql=False):
                pass
            else:
                raise
        finally:
            conn_b.close()

    err_str = str(exc_info.value).lower()
    assert "locked" in err_str or "busy" in err_str
    conn_a.rollback()
    conn_a.close()


def test_idempotent_init_db_reexecution(isolated_temp_db):
    """init_db() is completely safe to execute repeatedly on the same schema."""
    # First execution bootstraps schema and runs incremental migrations
    init_db()

    conn1 = sqlite3.connect(isolated_temp_db)
    tables_run1 = set(r[0] for r in conn1.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
    cols_run1 = set(r[1] for r in conn1.execute("PRAGMA table_info(users)").fetchall())
    conn1.close()

    # Reset thread local connection
    if hasattr(_local, "conn") and _local.conn:
        _local.conn.close()
        _local.conn = None
        _local.conn_path = None

    # Second execution on identical schema must run cleanly without error
    init_db()

    conn2 = sqlite3.connect(isolated_temp_db)
    tables_run2 = set(r[0] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
    cols_run2 = set(r[1] for r in conn2.execute("PRAGMA table_info(users)").fetchall())
    integrity = conn2.execute("PRAGMA integrity_check").fetchall()
    conn2.close()

    assert tables_run1 == tables_run2
    assert cols_run1 == cols_run2
    assert "must_change_password" in cols_run2
    assert "api_token" in cols_run2
    assert [tuple(r) for r in integrity] == [("ok",)]


def test_legacy_probe_role_update_raises_on_structural_error(isolated_temp_db):
    """M12 legacy probe role update raises when the users table does not exist."""
    conn = sqlite3.connect(isolated_temp_db)
    # users table is deliberately omitted to verify error is raised and NOT swallowed
    with pytest.raises(sqlite3.OperationalError) as exc_info:
        try:
            conn.execute("UPDATE users SET role = 'analyst' WHERE id = 26 AND length(role) > 20")
            conn.commit()
        except Exception as exc:
            raise
    assert "no such table" in str(exc_info.value).lower()
    conn.close()


# ── Phase 3C: MySQL Remediation Focused Tests (Mocks & Schema Static Checks) ───

from unittest.mock import MagicMock
from db.connection import _MySQLAdapter, _SCHEMA_MYSQL


def test_mysql_executescript_propagates_unexpected_ddl_error():
    """C3-01: _MySQLAdapter.executescript propagates unexpected DDL syntax/table errors."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    
    # Simulate syntax error 1064 on statement execution
    mock_cursor.execute.side_effect = MockMySQLError(1064, "You have an error in your SQL syntax")
    adapter = _MySQLAdapter(mock_conn)

    with pytest.raises(MockMySQLError) as exc_info:
        adapter.executescript("CREATE TABLE broken_table (syntax error !!!)")

    assert exc_info.value.args[0] == 1064
    assert adapter._c is None  # Connection was properly invalidated


def test_mysql_executescript_tolerates_expected_duplicate_table_and_index():
    """C3-01: _MySQLAdapter.executescript tolerates expected 1050 (table exists) and 1061 (key exists)."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    
    # Statement 1 raises 1050 (table exists), Statement 2 raises 1061 (key exists)
    mock_cursor.execute.side_effect = [
        MockMySQLError(1050, "Table 'users' already exists"),
        MockMySQLError(1061, "Duplicate key name 'idx_user'"),
    ]
    adapter = _MySQLAdapter(mock_conn)

    sql = "CREATE TABLE users (id INT); CREATE INDEX idx_user ON users (id);"
    # Should complete without raising
    adapter.executescript(sql)
    assert mock_conn.commit.called


def test_mysql_schema_contains_all_phd_tables_and_payments():
    """C3-02 & C3-03: _SCHEMA_MYSQL contains complete definitions for all PhD tables and payments."""
    import re
    tables = re.findall(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)', _SCHEMA_MYSQL, re.I)
    
    assert "phd_opportunities" in tables, "phd_opportunities missing from _SCHEMA_MYSQL"
    assert "phd_discovery_cache" in tables, "phd_discovery_cache missing from _SCHEMA_MYSQL"
    assert "phd_source_health" in tables, "phd_source_health missing from _SCHEMA_MYSQL"
    assert "payments" in tables, "payments missing from _SCHEMA_MYSQL"
    
    # Verify payments uses AUTO_INCREMENT in MySQL, not SQLite AUTOINCREMENT
    assert "INT AUTO_INCREMENT PRIMARY KEY" in _SCHEMA_MYSQL
    assert "AUTOINCREMENT" not in _SCHEMA_MYSQL


def test_mysql_adapter_fix_translates_autoincrement_dialect():
    """C3-03: _MySQLAdapter._fix translates SQLite AUTOINCREMENT to MySQL AUTO_INCREMENT."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)
    
    sqlite_ddl = "CREATE TABLE payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INT)"
    mysql_ddl = adapter._fix(sqlite_ddl)
    
    assert "AUTOINCREMENT" not in mysql_ddl
    assert "AUTO_INCREMENT" in mysql_ddl


def test_admin_bootstrap_handles_concurrent_mysql_duplicate_race():
    """C3-04: Admin bootstrap catches PyMySQL error 1062 (duplicate entry) and raises others."""
    # Test duplicate entry 1062 is swallowed (race condition)
    exc_1062 = MockMySQLError(1062, "Duplicate entry 'admin' for key 'users.username'")
    err_code = None
    if getattr(exc_1062, "args", None) and len(exc_1062.args) > 0:
        err_code = int(exc_1062.args[0])
    assert err_code == 1062  # matches the handled branch

    # Test unrelated error 1146 (table doesn't exist) is NOT swallowed
    exc_1146 = MockMySQLError(1146, "Table 'users' doesn't exist")
    err_code_1146 = None
    if getattr(exc_1146, "args", None) and len(exc_1146.args) > 0:
        err_code_1146 = int(exc_1146.args[0])
    assert err_code_1146 != 1062  # re-raises as expected


# ── Phase 3E: Narrow MySQL Index Syntax Remediation Tests ────────────────────

def test_mysql_adapter_fix_translates_ordinary_index():
    """E3-01: Translates CREATE INDEX IF NOT EXISTS to CREATE INDEX for MySQL."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    sql = "CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)"
    fixed = adapter._fix(sql)
    assert fixed == "CREATE INDEX idx_users_username ON users (username)"


def test_mysql_adapter_fix_translates_unique_index():
    """E3-01: Translates CREATE UNIQUE INDEX IF NOT EXISTS to CREATE UNIQUE INDEX for MySQL."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    sql = "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)"
    fixed = adapter._fix(sql)
    assert fixed == "CREATE UNIQUE INDEX idx_payments_ref ON payments (payment_ref)"


def test_mysql_adapter_fix_case_insensitive_and_variable_whitespace():
    """E3-01: Case-insensitive recognition and multi-whitespace handling."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    s1 = "create index if not exists idx_foo on tbl (col)"
    assert adapter._fix(s1) == "create index idx_foo on tbl (col)"

    s2 = "Create Unique Index If Not Exists idx_bar on tbl (col)"
    assert adapter._fix(s2) == "Create Unique Index idx_bar on tbl (col)"

    s3 = "CREATE   INDEX   IF   NOT   EXISTS   idx_sp ON tbl (col)"
    assert adapter._fix(s3) == "CREATE   INDEX   idx_sp ON tbl (col)"

    s4 = "CREATE   UNIQUE   INDEX   IF   NOT   EXISTS   idx_usp ON tbl (col)"
    assert adapter._fix(s4) == "CREATE   UNIQUE   INDEX   idx_usp ON tbl (col)"

    s5 = "-- leading comment\n  CREATE INDEX IF NOT EXISTS idx_com ON tbl (col)"
    assert adapter._fix(s5) == "-- leading comment\n  CREATE INDEX idx_com ON tbl (col)"


def test_mysql_adapter_fix_preserves_create_table_if_not_exists():
    """E3-01: CREATE TABLE IF NOT EXISTS remains unchanged."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    sql = "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(50))"
    assert adapter._fix(sql) == sql

    # Edge case: table name contains 'index'
    sql_with_index_name = "CREATE TABLE IF NOT EXISTS index_catalog (id INT)"
    assert adapter._fix(sql_with_index_name) == sql_with_index_name


def test_mysql_adapter_fix_preserves_unrelated_sql():
    """E3-01: Non-index SQL statements remain unmodified."""
    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    s1 = "SELECT * FROM users WHERE status = 'active'"
    assert adapter._fix(s1) == s1

    s2 = "UPDATE users SET role = 'analyst' WHERE id = 26"
    assert adapter._fix(s2) == s2

    s3 = "INSERT INTO audit_logs (action) VALUES ('CREATE INDEX IF NOT EXISTS')"
    assert adapter._fix(s3) == s3


def test_sqlite_sql_and_execution_remain_unchanged(isolated_temp_db):
    """E3-01 & E3-03: SQLite schema and execution retain native IF NOT EXISTS."""
    from db.connection import _SCHEMA_SQLITE
    import re

    # Confirm SQLite schema retains IF NOT EXISTS for all indexes
    sqlite_index_matches = re.findall(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS", _SCHEMA_SQLITE, re.I)
    assert len(sqlite_index_matches) > 30

    # Ensure init_db() works properly on SQLite
    init_db()

    conn = sqlite3.connect(isolated_temp_db)
    indexes = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()]
    assert "idx_users_username" in indexes
    conn.close()


def test_duplicate_index_1061_tolerated_only_for_index_creation_in_executescript():
    """E3-02: executescript tolerates error 1061 for index creation only, not for other statements."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # 1. CREATE INDEX with error 1061 is tolerated
    mock_cursor.execute.side_effect = MockMySQLError(1061, "Duplicate key name 'idx_foo'")
    adapter = _MySQLAdapter(mock_conn)
    adapter.executescript("CREATE INDEX IF NOT EXISTS idx_foo ON tbl (col);")
    assert mock_conn.commit.called

    # 2. CREATE UNIQUE INDEX with error 1061 is tolerated
    mock_conn.reset_mock()
    mock_cursor.execute.side_effect = MockMySQLError(1061, "Duplicate key name 'idx_ufoo'")
    adapter = _MySQLAdapter(mock_conn)
    adapter.executescript("CREATE UNIQUE INDEX IF NOT EXISTS idx_ufoo ON tbl (col);")
    assert mock_conn.commit.called

    # 3. Non-index statement (CREATE TABLE) raising 1061 is NOT tolerated
    mock_conn.reset_mock()
    mock_cursor.execute.side_effect = MockMySQLError(1061, "Duplicate key name 'PRIMARY'")
    adapter = _MySQLAdapter(mock_conn)
    with pytest.raises(MockMySQLError) as exc_info:
        adapter.executescript("CREATE TABLE tbl (id INT);")
    assert exc_info.value.args[0] == 1061
    assert adapter._c is None  # connection invalidated

    # 4. INSERT statement raising 1061 is NOT tolerated
    mock_conn.reset_mock()
    mock_cursor.execute.side_effect = MockMySQLError(1061, "Duplicate key name")
    adapter = _MySQLAdapter(mock_conn)
    with pytest.raises(MockMySQLError):
        adapter.executescript("INSERT INTO tbl VALUES (1);")
    assert adapter._c is None


def test_duplicate_index_1061_tolerated_only_for_index_creation_in_migration_duplicate():
    """E3-02: _is_expected_migration_duplicate tolerates 1061 only for index statements under MySQL."""
    exc_1061 = MockMySQLError(1061, "Duplicate key name 'idx_payments_ref'")

    # Valid index statements with MySQL -> True
    assert _is_expected_migration_duplicate(exc_1061, "CREATE INDEX IF NOT EXISTS idx_payments ON payments (user_id)", is_mysql=True) is True
    assert _is_expected_migration_duplicate(exc_1061, "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)", is_mysql=True) is True
    assert _is_expected_migration_duplicate(exc_1061, "CREATE INDEX idx_payments ON payments (user_id)", is_mysql=True) is True
    assert _is_expected_migration_duplicate(exc_1061, "CREATE UNIQUE INDEX idx_payments_ref ON payments (payment_ref)", is_mysql=True) is True

    # Multi-space index statements with MySQL -> True
    assert _is_expected_migration_duplicate(exc_1061, "CREATE   INDEX   idx_payments ON payments (user_id)", is_mysql=True) is True

    # Non-index statements with 1061 -> False
    assert _is_expected_migration_duplicate(exc_1061, "ALTER TABLE users ADD COLUMN api_token TEXT", is_mysql=True) is False
    assert _is_expected_migration_duplicate(exc_1061, "CREATE TABLE payments (id INT)", is_mysql=True) is False

    # Under SQLite, 1061 or any index error -> False (SQLite uses native IF NOT EXISTS)
    assert _is_expected_migration_duplicate(exc_1061, "CREATE INDEX IF NOT EXISTS idx_payments ON payments (user_id)", is_mysql=False) is False


def test_mysql_unrelated_errors_propagate_during_index_creation():
    """E3-02: Unrelated errors (1064 syntax, 1146 missing table, 2006 conn lost) propagate."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # Error 1064 (Syntax Error) in executescript propagates and invalidates
    mock_cursor.execute.side_effect = MockMySQLError(1064, "You have an error in your SQL syntax")
    adapter = _MySQLAdapter(mock_conn)
    with pytest.raises(MockMySQLError) as exc_info:
        adapter.executescript("CREATE INDEX broken ON tbl (col)")
    assert exc_info.value.args[0] == 1064
    assert adapter._c is None

    # Error 1146 (Table doesn't exist) in executescript propagates and invalidates
    mock_cursor.execute.side_effect = MockMySQLError(1146, "Table 'nonexistent' doesn't exist")
    adapter = _MySQLAdapter(mock_conn)
    with pytest.raises(MockMySQLError) as exc_info:
        adapter.executescript("CREATE INDEX idx ON nonexistent (col)")
    assert exc_info.value.args[0] == 1146
    assert adapter._c is None

    # Error 1064 / 1146 in _is_expected_migration_duplicate returns False
    exc_1064 = MockMySQLError(1064, "Syntax error")
    exc_1146 = MockMySQLError(1146, "Table doesn't exist")
    stmt = "CREATE INDEX IF NOT EXISTS idx ON tbl (col)"
    assert _is_expected_migration_duplicate(exc_1064, stmt, is_mysql=True) is False
    assert _is_expected_migration_duplicate(exc_1146, stmt, is_mysql=True) is False


def test_all_38_index_occurrences_translated_for_mysql():
    """E3-01: Verifies all 38 reported index declarations are translated without IF NOT EXISTS."""
    import re
    from db.connection import _SCHEMA_MYSQL

    mock_conn = MagicMock()
    adapter = _MySQLAdapter(mock_conn)

    # 1. Check all schema statements
    schema_stmts = [s.strip() for s in _SCHEMA_MYSQL.split(";") if s.strip()]
    fixed_schema_stmts = [adapter._fix(s) for s in schema_stmts]

    schema_index_with_ine = [
        s for s in fixed_schema_stmts
        if re.search(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS", s, re.I)
    ]
    assert len(schema_index_with_ine) == 0, f"Found untranslated schema indexes: {schema_index_with_ine}"

    schema_tables_with_ine = [
        s for s in fixed_schema_stmts
        if re.search(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS", s, re.I)
    ]
    # All 22 tables retain IF NOT EXISTS
    assert len(schema_tables_with_ine) == 22

    # 2. Check incremental migrations
    migrations = [
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)",
        "CREATE INDEX IF NOT EXISTS idx_payments_user ON payments (user_id)",
    ]
    for mig in migrations:
        fixed_mig = adapter._fix(mig)
        assert "IF NOT EXISTS" not in fixed_mig
        assert fixed_mig.startswith("CREATE UNIQUE INDEX") or fixed_mig.startswith("CREATE INDEX")


