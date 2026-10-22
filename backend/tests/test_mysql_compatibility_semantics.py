"""Focused regression tests for Evaluation Lab MySQL & SQLite compatibility semantics.

Validates:
1. _MySQLAdapter transaction boundary tracking, begin/commit/rollback semantics, failure invalidation.
2. LAB_INDEX_ALLOWLIST validation and create_lab_index_if_not_exists behavior across backends.
3. PyMySQL error 1061 race condition absorption vs unrelated DDL error propagation.
4. _extract_count handling of sqlite3.Row, DictCursor dicts, and tuples.
5. Atomic UPSERT in save_benchmark_scorecard preserving created_at.
6. Atomic multi-statement transactions in seed_lab_targets and seed_ground_truth_cases with rollback on failure.
"""

import json
import logging
import os
import sqlite3
import sys
from unittest.mock import MagicMock, patch
import pytest

try:
    import db.connection as conn_mod
    import db.lab as lab_mod
    from db.connection import (
        _MySQLAdapter,
        LAB_INDEX_ALLOWLIST,
        create_lab_index_if_not_exists,
        _extract_count,
    )
    from db.lab import (
        init_lab_tables,
        save_benchmark_scorecard,
        get_benchmark_scorecard,
        seed_lab_targets,
        seed_ground_truth_cases,
    )
except ImportError:
    import backend.db.connection as conn_mod
    import backend.db.lab as lab_mod
    from backend.db.connection import (
        _MySQLAdapter,
        LAB_INDEX_ALLOWLIST,
        create_lab_index_if_not_exists,
        _extract_count,
    )
    from backend.db.lab import (
        init_lab_tables,
        save_benchmark_scorecard,
        get_benchmark_scorecard,
        seed_lab_targets,
        seed_ground_truth_cases,
    )


class TestMySQLAdapterTransactions:
    def test_default_autocommit_per_statement(self):
        mock_conn = MagicMock()
        adapter = _MySQLAdapter(mock_conn)

        assert adapter._in_transaction is False
        adapter.execute("SELECT 1")
        mock_conn.commit.assert_called_once()

    def test_begin_pauses_per_statement_commit(self):
        mock_conn = MagicMock()
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        assert adapter._in_transaction is True
        mock_conn.begin.assert_called_once()

        mock_conn.reset_mock()
        adapter.execute("INSERT INTO test VALUES (?)", (1,))
        adapter.execute("INSERT INTO test VALUES (?)", (2,))

        # Neither execution should have called commit while in transaction
        assert mock_conn.commit.call_count == 0

        adapter.commit()
        assert mock_conn.commit.call_count == 1
        assert adapter._in_transaction is False

    def test_rollback_resets_transaction_state(self):
        mock_conn = MagicMock()
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        assert adapter._in_transaction is True

        adapter.execute("UPDATE test SET x = 1")
        adapter.rollback()

        mock_conn.rollback.assert_called_once()
        assert adapter._in_transaction is False

    def test_commit_failure_invalidates_and_raises(self):
        mock_conn = MagicMock()
        mock_conn.commit.side_effect = RuntimeError("Network error during commit")
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        assert adapter._in_transaction is True

        with pytest.raises(RuntimeError, match="Network error during commit"):
            adapter.commit()

        # State must NOT remain stuck in transaction
        assert adapter._in_transaction is False
        # Connection must be closed/invalidated
        mock_conn.close.assert_called_once()
        assert adapter._c is None

    def test_rollback_failure_invalidates_and_raises(self):
        mock_conn = MagicMock()
        mock_conn.rollback.side_effect = RuntimeError("Network error during rollback")
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        assert adapter._in_transaction is True

        with pytest.raises(RuntimeError, match="Network error during rollback"):
            adapter.rollback()

        assert adapter._in_transaction is False
        mock_conn.close.assert_called_once()
        assert adapter._c is None

    def test_begin_when_already_in_transaction_raises(self):
        mock_conn = MagicMock()
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        assert adapter._in_transaction is True

        with pytest.raises(sqlite3.OperationalError, match="cannot start a transaction within a transaction"):
            adapter.begin()

    def test_execute_after_invalidation_fails_fast(self):
        mock_conn = MagicMock()
        mock_conn.commit.side_effect = RuntimeError("Broken")
        adapter = _MySQLAdapter(mock_conn)

        adapter.begin()
        with pytest.raises(RuntimeError):
            adapter.commit()

        # Subsequent calls on invalidated adapter must fail immediately
        with pytest.raises(sqlite3.OperationalError, match="invalidated connection"):
            adapter.execute("SELECT 1")


class TestExtractCount:
    def test_extract_from_sqlite_row(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT 42 AS total_count")
        row = cur.fetchone()
        assert _extract_count(row, "total_count") == 42
        conn.close()

    def test_extract_from_dict_cursor(self):
        dict_row = {"total_count": 88}
        assert _extract_count(dict_row, "total_count") == 88

    def test_extract_from_dict_fallback_first_value(self):
        raw_dict = {"COUNT(*)": 17}
        assert _extract_count(raw_dict, "total_count") == 17

    def test_extract_from_tuple(self):
        tuple_row = (99,)
        assert _extract_count(tuple_row) == 99

    def test_extract_from_empty_or_none(self):
        assert _extract_count(None) == 0
        assert _extract_count({}) == 0


class TestLabIndexAllowlistAndCreation:
    def test_unpermitted_index_raises_value_error(self):
        with pytest.raises(ValueError, match="not permitted by LAB_INDEX_ALLOWLIST"):
            create_lab_index_if_not_exists("lab_targets", "idx_unauthorized_index")

    def test_permitted_indexes_match_expected_inventory(self):
        expected_names = {
            "idx_lab_targets_kind",
            "idx_lab_targets_enabled",
            "idx_lab_gt_dataset",
            "idx_lab_gt_target",
            "idx_lab_gt_split",
            "idx_lab_bench_engine",
            "idx_lab_bench_target",
            "idx_lab_bench_status",
        }
        actual_names = {idx for (_, idx) in LAB_INDEX_ALLOWLIST}
        assert actual_names == expected_names

    def test_sqlite_index_creation_with_explicit_connection(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE lab_targets (kind VARCHAR(32))")
        create_lab_index_if_not_exists("lab_targets", "idx_lab_targets_kind", db=conn)

        # Re-running is idempotent
        create_lab_index_if_not_exists("lab_targets", "idx_lab_targets_kind", db=conn)

        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_lab_targets_kind'"
        )
        assert cur.fetchone() is not None
        conn.close()

    def test_mysql_catches_error_1061_race_condition(self, monkeypatch):
        mock_db = MagicMock()
        mock_db._c = MagicMock()  # Triggers is_mysql = True

        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None

        class MockPyMySQLError(Exception):
            def __init__(self, errno, msg):
                super().__init__(msg)
                self.args = (errno, msg)

        # Test error 1061 is absorbed
        monkeypatch.setattr(conn_mod, "_USE_MYSQL", True)
        mock_db.execute.side_effect = [
            mock_cur,
            MockPyMySQLError(1061, "Duplicate key name 'idx_lab_targets_kind'"),
        ]
        # Should not raise
        create_lab_index_if_not_exists("lab_targets", "idx_lab_targets_kind", db=mock_db)

    def test_mysql_reraises_unrelated_ddl_error(self, monkeypatch):
        mock_db = MagicMock()
        mock_db._c = MagicMock()

        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None

        class MockPyMySQLError(Exception):
            def __init__(self, errno, msg):
                super().__init__(msg)
                self.args = (errno, msg)

        monkeypatch.setattr(conn_mod, "_USE_MYSQL", True)
        # Error 1064 is syntax error or 1146 table doesn't exist
        mock_db.execute.side_effect = [
            mock_cur,
            MockPyMySQLError(1146, "Table doesn't exist"),
        ]
        with pytest.raises(MockPyMySQLError):
            create_lab_index_if_not_exists("lab_targets", "idx_lab_targets_kind", db=mock_db)


class TestScorecardUpsertPreservesCreatedAt:
    def test_scorecard_upsert_preserves_created_at(self, monkeypatch, tmp_path):
        test_db = tmp_path / "upsert_test.db"
        monkeypatch.setenv("DB_PATH", str(test_db))
        init_lab_tables()

        scorecard = {
            "benchmark_id": "bench_test_upsert_001",
            "protocol_version": "1.0.0",
            "engine_id": "test_engine",
            "target_id": "test_target",
            "dataset_id": "hexaguard_bench_core",
            "dataset_version": "1.0.0",
            "execution_status": "COMPLETED",
            "benchmark_status": "PASS",
            "status_reasons": ["All checks passed"],
            "counts": {"total": 10, "passed": 10},
            "metrics": {"accuracy": 1.0},
            "critical_review_flags": [],
            "scorecard_json": {},
        }

        # 1. First save (insert)
        bench_id = save_benchmark_scorecard(scorecard)
        row1 = get_benchmark_scorecard(bench_id)
        assert row1 is not None
        initial_created_at = row1["created_at"]
        assert row1["benchmark_status"] == "PASS"

        # 2. Second save (update) with modified metrics and status
        scorecard["benchmark_status"] = "FAIL"
        scorecard["status_reasons"] = ["Threshold breached"]
        save_benchmark_scorecard(scorecard)

        row2 = get_benchmark_scorecard(bench_id)
        assert row2 is not None
        # created_at MUST be preserved untouched
        assert row2["created_at"] == initial_created_at
        # Updated fields must reflect new values
        assert row2["benchmark_status"] == "FAIL"
        assert row2["status_reasons"] == ["Threshold breached"]


class TestSeedingTransactions:
    """Tests atomic seeding boundaries on real SQLite and mocked MySQL."""

    def test_seed_lab_targets_rollback_on_failure_real_sqlite(self, tmp_path, monkeypatch, caplog):
        """On real SQLite, verify that if an error occurs mid-seeding, all inserts roll back and confirmed rollback is logged."""
        test_db = tmp_path / "seed_targets_rollback.db"
        monkeypatch.setenv("DB_PATH", str(test_db))
        init_lab_tables()

        # Target 1 is valid, Target 2 has name=None violating NOT NULL constraint
        seed_data = [
            {"id": "t1", "name": "Target 1", "kind": "local_source"},
            {"id": "t2", "name": None, "kind": "local_source"},
        ]
        seed_file = tmp_path / "test_targets.json"
        seed_file.write_text(json.dumps(seed_data), encoding="utf-8")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(sqlite3.IntegrityError):
                seed_lab_targets(str(seed_file))

        # Verification: Rollback succeeded, 0 rows committed!
        db = conn_mod._get_db()
        row = db.execute("SELECT COUNT(*) AS total_count FROM lab_targets").fetchone()
        assert _extract_count(row, "total_count") == 0

        # Verification: Log accurately reports confirmed rollback
        assert "Failed to seed lab targets; transaction rolled back:" in caplog.text
        assert "rollback unconfirmed" not in caplog.text

    def test_seed_ground_truth_rollback_on_failure_real_sqlite(self, tmp_path, monkeypatch, caplog):
        """On real SQLite, verify that if ground truth seeding fails, all inserts roll back and confirmed rollback is logged."""
        test_db = tmp_path / "seed_gt_rollback.db"
        monkeypatch.setenv("DB_PATH", str(test_db))
        init_lab_tables()

        # Case 1 is valid, Case 2 has vulnerability_type=None violating NOT NULL
        gt_data = [
            {"case_id": "case_01", "target_id": "t1", "vulnerability_type": "sqli"},
            {"case_id": "case_02", "target_id": "t2", "vulnerability_type": None},
        ]
        seed_file = tmp_path / "test_gt.json"
        seed_file.write_text(json.dumps(gt_data), encoding="utf-8")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(sqlite3.IntegrityError):
                seed_ground_truth_cases(str(seed_file))

        db = conn_mod._get_db()
        row = db.execute("SELECT COUNT(*) AS total_count FROM lab_ground_truth").fetchone()
        assert _extract_count(row, "total_count") == 0

        assert "Failed to seed ground truth cases; transaction rolled back:" in caplog.text
        assert "rollback unconfirmed" not in caplog.text

    def test_seed_lab_targets_mysql_uses_explicit_transaction(self, tmp_path, monkeypatch):
        """On MySQL (mocked), verify that seed_lab_targets begins and commits explicitly."""
        seed_data = [{"id": "t1", "name": "Target 1", "kind": "local_source"}]
        seed_file = tmp_path / "test_mysql_targets.json"
        seed_file.write_text(json.dumps(seed_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        mock_db.execute.return_value.fetchone.return_value = {"total_count": 0}

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        inserted = seed_lab_targets(str(seed_file))
        assert inserted == 1
        mock_db.begin.assert_called_once()
        mock_db.commit.assert_called_once()
        assert mock_db.rollback.call_count == 0

    def test_seed_lab_targets_mysql_rolls_back_and_logs_confirmed_on_failure(self, tmp_path, monkeypatch, caplog):
        """On MySQL (mocked), verify that when insert fails and rollback succeeds, rollback is confirmed in logs."""
        seed_data = [{"id": "t1", "name": "Target 1", "kind": "local_source"}]
        seed_file = tmp_path / "test_mysql_targets_fail.json"
        seed_file.write_text(json.dumps(seed_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        count_cur = MagicMock()
        count_cur.fetchone.return_value = {"total_count": 0}

        mock_db.execute.side_effect = [
            count_cur,
            RuntimeError("MySQL connection lost during insert"),
        ]

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="MySQL connection lost during insert"):
                seed_lab_targets(str(seed_file))

        mock_db.begin.assert_called_once()
        mock_db.rollback.assert_called_once()
        assert mock_db.commit.call_count == 0

        assert "Failed to seed lab targets; transaction rolled back: MySQL connection lost during insert" in caplog.text
        assert "rollback unconfirmed" not in caplog.text

    def test_seed_lab_targets_failed_rollback_logs_unconfirmed_and_preserves_original_exc(self, tmp_path, monkeypatch, caplog):
        """Verify that if rollback fails, log records unconfirmed status with rollback error, and original exception is preserved."""
        seed_data = [{"id": "t1", "name": "Target 1", "kind": "local_source"}]
        seed_file = tmp_path / "test_mysql_targets_rb_fail.json"
        seed_file.write_text(json.dumps(seed_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        count_cur = MagicMock()
        count_cur.fetchone.return_value = {"total_count": 0}

        mock_db.execute.side_effect = [
            count_cur,
            RuntimeError("Primary insert failure"),
        ]
        mock_db.rollback.side_effect = RuntimeError("Socket closed during rollback")

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            # Must raise the original error, NOT the rollback error
            with pytest.raises(RuntimeError, match="Primary insert failure"):
                seed_lab_targets(str(seed_file))

        assert "Failed to seed lab targets; transaction rollback unconfirmed" in caplog.text
        assert "Socket closed during rollback" in caplog.text
        assert "Primary insert failure" in caplog.text
        assert "transaction rolled back:" not in caplog.text

    def test_seed_lab_targets_commit_failure_logs_unconfirmed_and_preserves_commit_exc(self, tmp_path, monkeypatch, caplog):
        """Verify that when commit fails on _MySQLAdapter, connection is invalidated, rollback failure is caught, and status is logged as unconfirmed."""
        seed_data = [{"id": "t1", "name": "Target 1", "kind": "local_source"}]
        seed_file = tmp_path / "test_mysql_targets_commit_fail.json"
        seed_file.write_text(json.dumps(seed_data), encoding="utf-8")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = {"total_count": 0}
        mock_conn.cursor.return_value = mock_cur
        # 1st commit (autocommit during initial SELECT COUNT(*)) succeeds;
        # 2nd commit (explicit db.commit() ending the seed transaction) fails.
        mock_conn.commit.side_effect = [None, RuntimeError("Deadlock on commit")]

        adapter = _MySQLAdapter(mock_conn)

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: adapter)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            # Must raise the original commit error
            with pytest.raises(RuntimeError, match="Deadlock on commit"):
                seed_lab_targets(str(seed_file))

        assert "Failed to seed lab targets; transaction rollback unconfirmed" in caplog.text
        assert "cannot rollback invalidated connection" in caplog.text
        assert "Deadlock on commit" in caplog.text
        assert "transaction rolled back:" not in caplog.text

    def test_seed_ground_truth_mysql_uses_explicit_transaction(self, tmp_path, monkeypatch):
        """On MySQL (mocked), verify that seed_ground_truth_cases begins and commits explicitly."""
        gt_data = [{"case_id": "case_01", "target_id": "t1", "vulnerability_type": "sqli"}]
        seed_file = tmp_path / "test_mysql_gt.json"
        seed_file.write_text(json.dumps(gt_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        mock_db.execute.return_value.fetchone.return_value = {"total_count": 0}

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        inserted = seed_ground_truth_cases(str(seed_file))
        assert inserted == 1
        mock_db.begin.assert_called_once()
        mock_db.commit.assert_called_once()
        assert mock_db.rollback.call_count == 0

    def test_seed_ground_truth_mysql_rolls_back_and_logs_confirmed_on_failure(self, tmp_path, monkeypatch, caplog):
        """On MySQL (mocked), verify that when case insert fails and rollback succeeds, rollback is confirmed in logs."""
        gt_data = [{"case_id": "case_01", "target_id": "t1", "vulnerability_type": "sqli"}]
        seed_file = tmp_path / "test_mysql_gt_fail.json"
        seed_file.write_text(json.dumps(gt_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        count_cur = MagicMock()
        count_cur.fetchone.return_value = {"total_count": 0}

        mock_db.execute.side_effect = [
            count_cur,
            RuntimeError("MySQL connection lost during case insert"),
        ]

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="MySQL connection lost during case insert"):
                seed_ground_truth_cases(str(seed_file))

        mock_db.begin.assert_called_once()
        mock_db.rollback.assert_called_once()
        assert mock_db.commit.call_count == 0

        assert "Failed to seed ground truth cases; transaction rolled back: MySQL connection lost during case insert" in caplog.text
        assert "rollback unconfirmed" not in caplog.text

    def test_seed_ground_truth_failed_rollback_logs_unconfirmed_and_preserves_original_exc(self, tmp_path, monkeypatch, caplog):
        """Verify that if ground truth rollback fails, log records unconfirmed status with rollback error, and original error is preserved."""
        gt_data = [{"case_id": "case_01", "target_id": "t1", "vulnerability_type": "sqli"}]
        seed_file = tmp_path / "test_mysql_gt_rb_fail.json"
        seed_file.write_text(json.dumps(gt_data), encoding="utf-8")

        mock_db = MagicMock()
        mock_db._c = MagicMock()
        count_cur = MagicMock()
        count_cur.fetchone.return_value = {"total_count": 0}

        mock_db.execute.side_effect = [
            count_cur,
            RuntimeError("Primary GT insert failure"),
        ]
        mock_db.rollback.side_effect = RuntimeError("Broken pipe on GT rollback")

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: mock_db)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="Primary GT insert failure"):
                seed_ground_truth_cases(str(seed_file))

        assert "Failed to seed ground truth cases; transaction rollback unconfirmed" in caplog.text
        assert "Broken pipe on GT rollback" in caplog.text
        assert "Primary GT insert failure" in caplog.text
        assert "transaction rolled back:" not in caplog.text

    def test_seed_ground_truth_commit_failure_logs_unconfirmed_and_preserves_commit_exc(self, tmp_path, monkeypatch, caplog):
        """Verify that when commit fails on _MySQLAdapter for ground truth, rollback failure is handled and logged as unconfirmed."""
        gt_data = [{"case_id": "case_01", "target_id": "t1", "vulnerability_type": "sqli"}]
        seed_file = tmp_path / "test_mysql_gt_commit_fail.json"
        seed_file.write_text(json.dumps(gt_data), encoding="utf-8")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = {"total_count": 0}
        mock_conn.cursor.return_value = mock_cur
        # 1st commit (autocommit during initial SELECT COUNT(*)) succeeds;
        # 2nd commit (explicit db.commit() ending the seed transaction) fails.
        mock_conn.commit.side_effect = [None, RuntimeError("Commit timeout on GT")]

        adapter = _MySQLAdapter(mock_conn)

        monkeypatch.setattr(lab_mod, "init_lab_tables", lambda: None)
        monkeypatch.setattr(lab_mod, "_get_db", lambda: adapter)
        monkeypatch.setattr(lab_mod, "_USE_MYSQL", True)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="Commit timeout on GT"):
                seed_ground_truth_cases(str(seed_file))

        assert "Failed to seed ground truth cases; transaction rollback unconfirmed" in caplog.text
        assert "cannot rollback invalidated connection" in caplog.text
        assert "Commit timeout on GT" in caplog.text
        assert "transaction rolled back:" not in caplog.text


class TestMySQLDocumentedVersionRequirement:
    """Verifies that authoritative documentation specifies the MySQL server version requirement."""

    def test_readme_documents_mysql_minimum_version_and_scope(self):
        readme_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "README.md",
        )
        assert os.path.exists(readme_path), f"README.md not found at {readme_path}"

        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must explicitly document 8.0.19 or later for MySQL backend
        assert "8.0.19 or later" in content
        assert "MySQL Backend Version Requirement" in content
        # Must clearly mention row-alias / new_row syntax reason
        assert "new_row" in content
        assert "save_benchmark_scorecard" in content
        # Must scope non-support for MySQL 5.7 and older 8.0 releases
        assert "MySQL 5.7" in content
        assert "8.0.18" in content
        # Must state MariaDB compatibility is not established
        assert "MariaDB" in content
        # Must explicitly declare no live MySQL server validation has been performed
        assert "no live MySQL server validation" in content
