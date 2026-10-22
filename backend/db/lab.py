"""SecuraX Evaluation Lab — Database Persistence Layer.

Handles lab_targets storage, querying, health updates, and user acknowledgement auditing.
Compatible with SQLite (default) and MySQL.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from db.connection import (
        _get_db, _exec, _USE_MYSQL,
        LAB_INDEX_ALLOWLIST, create_lab_index_if_not_exists, _extract_count,
    )
    from db.audit import log_event
except ImportError:
    from backend.db.connection import (
        _get_db, _exec, _USE_MYSQL,
        LAB_INDEX_ALLOWLIST, create_lab_index_if_not_exists, _extract_count,
    )
    from backend.db.audit import log_event

logger = logging.getLogger(__name__)


def init_lab_tables(db=None) -> None:
    """Ensure the lab_targets, lab_ground_truth, and lab_benchmarks tables exist.

    Uses bounded VARCHAR primary keys and indexed columns for full MySQL InnoDB
    and SQLite compatibility.
    """
    if db is None:
        db = _get_db()
    # 1. Targets (Phase 1)
    db.execute("""
        CREATE TABLE IF NOT EXISTS lab_targets (
            id                   VARCHAR(64) PRIMARY KEY,
            name                 VARCHAR(255) NOT NULL,
            kind                 VARCHAR(32) NOT NULL,
            scanners             TEXT NOT NULL DEFAULT '[]',
            address              VARCHAR(500),
            source_url           VARCHAR(500),
            license              VARCHAR(64),
            legal_note           TEXT,
            permitted_scan_types TEXT NOT NULL DEFAULT '[]',
            rate_limit           INTEGER NOT NULL DEFAULT 10,
            max_concurrency      INTEGER NOT NULL DEFAULT 1,
            enabled              INTEGER NOT NULL DEFAULT 1,
            manifest_path        VARCHAR(500),
            difficulty           VARCHAR(32) DEFAULT 'medium',
            resource_needs       TEXT DEFAULT '{}',
            setup_status         VARCHAR(32) NOT NULL DEFAULT 'ready',
            last_health_check    VARCHAR(50),
            auth_source_url      VARCHAR(500),
            auth_verified_at     VARCHAR(50),
            auth_expires_at      VARCHAR(50),
            expected_fingerprint VARCHAR(128),
            created_at           VARCHAR(50) NOT NULL,
            updated_at           VARCHAR(50) NOT NULL
        )
    """)

    # 2. Ground Truth Registry (Phase 2)
    db.execute("""
        CREATE TABLE IF NOT EXISTS lab_ground_truth (
            case_id             VARCHAR(128) PRIMARY KEY,
            dataset_id          VARCHAR(64) NOT NULL,
            dataset_version     VARCHAR(32) NOT NULL,
            split               VARCHAR(32) NOT NULL DEFAULT 'dev',
            target_id           VARCHAR(64) NOT NULL,
            vulnerability_type  VARCHAR(255) NOT NULL,
            cwe                 VARCHAR(64) NOT NULL,
            truth_state         VARCHAR(32) NOT NULL,
            expected_severity   VARCHAR(32) NOT NULL,
            location            TEXT NOT NULL DEFAULT '{}',
            expected_evidence   TEXT NOT NULL DEFAULT '',
            verification_method VARCHAR(64) NOT NULL,
            eligible_engines    TEXT NOT NULL DEFAULT '[]',
            preconditions       TEXT NOT NULL DEFAULT '{}',
            difficulty          INTEGER NOT NULL DEFAULT 1,
            hint                TEXT,
            explanation         TEXT,
            learn_ref           TEXT,
            is_negative_control INTEGER NOT NULL DEFAULT 0,
            source_license      VARCHAR(64),
            checksum            VARCHAR(64),
            reviewers           TEXT NOT NULL DEFAULT '[]',
            last_validated      VARCHAR(50),
            created_at          VARCHAR(50) NOT NULL,
            updated_at          VARCHAR(50) NOT NULL
        )
    """)

    # 3. Benchmarks & Scorecards (Phase 2)
    db.execute("""
        CREATE TABLE IF NOT EXISTS lab_benchmarks (
            benchmark_id          VARCHAR(64) PRIMARY KEY,
            protocol_version      VARCHAR(32) NOT NULL,
            engine_id             VARCHAR(64) NOT NULL,
            target_id             VARCHAR(64) NOT NULL,
            dataset_id            VARCHAR(64) NOT NULL,
            dataset_version       VARCHAR(32) NOT NULL,
            execution_status      VARCHAR(32) NOT NULL,
            benchmark_status      VARCHAR(32) NOT NULL,
            status_reasons        TEXT NOT NULL DEFAULT '[]',
            summary_counts        TEXT NOT NULL DEFAULT '{}',
            metrics               TEXT NOT NULL DEFAULT '{}',
            critical_review_flags TEXT NOT NULL DEFAULT '[]',
            scorecard_json        TEXT NOT NULL DEFAULT '{}',
            repeated_run_stats    TEXT DEFAULT '{}',
            created_at            VARCHAR(50) NOT NULL,
            updated_at            VARCHAR(50) NOT NULL
        )
    """)
    for (tbl, idx) in LAB_INDEX_ALLOWLIST:
        create_lab_index_if_not_exists(tbl, idx, db=db)
    db.commit()



def seed_lab_targets(seed_file_path: Optional[str] = None) -> int:
    """Seed lab_targets from data file if table is empty or update missing entries."""
    init_lab_tables()
    db = _get_db()
    row = db.execute("SELECT COUNT(*) AS total_count FROM lab_targets").fetchone()
    count = _extract_count(row, "total_count")
    if count > 0:
        return count

    if not seed_file_path:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        seed_file_path = os.path.join(base_dir, "data", "lab_targets_seed.json")

    if not os.path.exists(seed_file_path):
        logger.warning("Lab seed file not found: %s", seed_file_path)
        return 0

    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            targets = json.load(f)
    except Exception as exc:
        logger.error("Failed to parse lab seed file: %s", exc)
        return 0

    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    is_mysql = getattr(db, "_c", None) is not None or _USE_MYSQL
    conflict_clause = " ON DUPLICATE KEY UPDATE id = id" if is_mysql else " ON CONFLICT(id) DO NOTHING"
    insert_sql = """
        INSERT INTO lab_targets (
            id, name, kind, scanners, address, source_url, license, legal_note,
            permitted_scan_types, rate_limit, max_concurrency, enabled, manifest_path,
            difficulty, resource_needs, setup_status, last_health_check,
            auth_source_url, auth_verified_at, auth_expires_at, expected_fingerprint,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """ + conflict_clause

    if hasattr(db, "begin"):
        db.begin()

    try:
        for t in targets:
            db.execute(insert_sql, (
                t["id"],
                t["name"],
                t["kind"],
                json.dumps(t.get("scanners", [])),
                t.get("address"),
                t.get("source_url"),
                t.get("license"),
                t.get("legal_note"),
                json.dumps(t.get("permitted_scan_types", [])),
                int(t.get("rate_limit", 10)),
                int(t.get("max_concurrency", 1)),
                int(t.get("enabled", 1)),
                t.get("manifest_path"),
                t.get("difficulty", "medium"),
                json.dumps(t.get("resource_needs", {})),
                t.get("setup_status", "ready"),
                t.get("last_health_check"),
                t.get("auth_source_url"),
                t.get("auth_verified_at"),
                t.get("auth_expires_at"),
                t.get("expected_fingerprint"),
                now,
                now,
            ))
            inserted += 1
        db.commit()
    except Exception as exc:
        rollback_exc = None
        try:
            db.rollback()
        except Exception as r_err:
            rollback_exc = r_err

        if rollback_exc is None:
            logger.error("Failed to seed lab targets; transaction rolled back: %s", exc)
        else:
            logger.error(
                "Failed to seed lab targets; transaction rollback unconfirmed (rollback error: %s): %s",
                rollback_exc,
                exc,
            )
        raise

    logger.info("Seeded %d lab targets from %s", inserted, seed_file_path)
    return inserted


def get_lab_target(target_id: str) -> Optional[dict]:
    """Retrieve a single lab target by ID."""
    init_lab_tables()
    db = _get_db()
    row = db.execute("SELECT * FROM lab_targets WHERE id = ?", (target_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["scanners"] = json.loads(d.get("scanners") or "[]")
    d["permitted_scan_types"] = json.loads(d.get("permitted_scan_types") or "[]")
    d["resource_needs"] = json.loads(d.get("resource_needs") or "{}")
    d["enabled"] = bool(d.get("enabled", 1))
    return d


def list_lab_targets(kind: Optional[str] = None, enabled_only: bool = False) -> list[dict]:
    """List lab targets with optional kind and enabled filters."""
    init_lab_tables()
    db = _get_db()
    query = "SELECT * FROM lab_targets"
    params: list[Any] = []
    clauses: list[str] = []

    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    if enabled_only:
        clauses.append("enabled = 1")

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY kind, id ASC"
    rows = db.execute(query, params).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["scanners"] = json.loads(d.get("scanners") or "[]")
        d["permitted_scan_types"] = json.loads(d.get("permitted_scan_types") or "[]")
        d["resource_needs"] = json.loads(d.get("resource_needs") or "{}")
        d["enabled"] = bool(d.get("enabled", 1))
        d["is_executable"] = (d["kind"] != "public_reference" and d["enabled"])
        results.append(d)
    return results


def update_target_health(target_id: str, status: str, check_time: Optional[str] = None) -> bool:
    """Update last health check status for a target."""
    now = check_time or datetime.now(timezone.utc).isoformat()
    try:
        _exec(
            "UPDATE lab_targets SET setup_status = ?, last_health_check = ?, updated_at = ? WHERE id = ?",
            (status, now, now, target_id),
        )
        return True
    except Exception as exc:
        logger.warning("Failed to update target health for %s: %s", target_id, exc)
        return False


def record_user_acknowledgement(
    user_id: int,
    username: str,
    target_id: str,
    scope: str,
    scan_type: str,
    ip_address: str = "",
) -> None:
    """Record mandatory user acknowledgement for scanning an authorized public target."""
    log_event(
        action="lab_target_acknowledgement",
        username=username,
        user_id=user_id,
        category="lab_authorization",
        resource=target_id,
        ip_address=ip_address,
        status="acknowledged",
        details=f"user={username} acknowledged authorized testing scope for target={target_id} scan_type={scan_type} scope={scope}",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2: Ground Truth & Benchmark Persistence
# ══════════════════════════════════════════════════════════════════════════════

def seed_ground_truth_cases(seed_file_path: Optional[str] = None) -> int:
    """Seed ground truth cases from seed JSON file if table is empty."""
    init_lab_tables()
    db = _get_db()
    row = db.execute("SELECT COUNT(*) AS total_count FROM lab_ground_truth").fetchone()
    count = _extract_count(row, "total_count")
    if count > 0:
        return count

    if not seed_file_path:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        seed_file_path = os.path.join(base_dir, "data", "ground_truth_seed.json")

    if not os.path.exists(seed_file_path):
        logger.warning("Ground truth seed file not found: %s", seed_file_path)
        return 0

    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            cases = json.load(f)
    except Exception as exc:
        logger.error("Failed to parse ground truth seed file: %s", exc)
        return 0

    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    is_mysql = getattr(db, "_c", None) is not None or _USE_MYSQL
    conflict_clause = " ON DUPLICATE KEY UPDATE case_id = case_id" if is_mysql else " ON CONFLICT(case_id) DO NOTHING"
    insert_sql = """
        INSERT INTO lab_ground_truth (
            case_id, dataset_id, dataset_version, split, target_id, vulnerability_type,
            cwe, truth_state, expected_severity, location, expected_evidence,
            verification_method, eligible_engines, preconditions, difficulty,
            hint, explanation, learn_ref, is_negative_control, source_license,
            checksum, reviewers, last_validated, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """ + conflict_clause

    if hasattr(db, "begin"):
        db.begin()

    try:
        for c in cases:
            db.execute(insert_sql, (
                c["case_id"],
                c.get("dataset_id", "hexaguard_bench_core"),
                c.get("dataset_version", "1.0.0"),
                c.get("split", "dev"),
                c.get("target_id", ""),
                c.get("vulnerability_type", ""),
                c.get("cwe", "CWE-UNKNOWN"),
                c.get("truth_state", "CONFIRMED_VULNERABLE"),
                c.get("expected_severity", "medium"),
                json.dumps(c.get("location", {})),
                c.get("expected_evidence", ""),
                c.get("verification_method", "manual_audit"),
                json.dumps(c.get("eligible_engines", [])),
                json.dumps(c.get("preconditions", {})),
                int(c.get("difficulty", 1)),
                c.get("hint", ""),
                c.get("explanation", ""),
                c.get("learn_ref", ""),
                1 if c.get("is_negative_control") else 0,
                c.get("source_license", ""),
                c.get("checksum", ""),
                json.dumps(c.get("reviewers", [])),
                c.get("last_validated", now),
                now,
                now,
            ))
            inserted += 1
        db.commit()
    except Exception as exc:
        rollback_exc = None
        try:
            db.rollback()
        except Exception as r_err:
            rollback_exc = r_err

        if rollback_exc is None:
            logger.error("Failed to seed ground truth cases; transaction rolled back: %s", exc)
        else:
            logger.error(
                "Failed to seed ground truth cases; transaction rollback unconfirmed (rollback error: %s): %s",
                rollback_exc,
                exc,
            )
        raise

    logger.info("Seeded %d ground truth cases from %s", inserted, seed_file_path)
    return inserted


def get_ground_truth_case_by_id(case_id: str) -> Optional[dict]:
    """Retrieve a single ground truth case by its case_id."""
    init_lab_tables()
    db = _get_db()
    row = db.execute("SELECT * FROM lab_ground_truth WHERE case_id = ?", (case_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["location"] = json.loads(d.get("location") or "{}")
    d["eligible_engines"] = json.loads(d.get("eligible_engines") or "[]")
    d["preconditions"] = json.loads(d.get("preconditions") or "{}")
    d["reviewers"] = json.loads(d.get("reviewers") or "[]")
    d["is_negative_control"] = bool(d.get("is_negative_control", 0))
    return d


def list_ground_truth_cases_db(
    dataset_id: Optional[str] = None,
    split: Optional[str] = "dev",
    target_id: Optional[str] = None,
) -> list[dict]:
    """List ground truth cases from database with optional filters.

    Default split is 'dev' to prevent unintentional leakage of held-out benchmark cases.
    Pass split='heldout' for held-out evaluation, or split='all' (or None) to load all splits.
    """
    init_lab_tables()
    db = _get_db()
    query = "SELECT * FROM lab_ground_truth"
    params: list[Any] = []
    clauses: list[str] = []

    if dataset_id:
        clauses.append("dataset_id = ?")
        params.append(dataset_id)
    if split and str(split).lower() != "all":
        clauses.append("split = ?")
        params.append(str(split).lower())
    if target_id:
        clauses.append("target_id = ?")
        params.append(target_id)

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY case_id ASC"
    rows = db.execute(query, params).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["location"] = json.loads(d.get("location") or "{}")
        d["eligible_engines"] = json.loads(d.get("eligible_engines") or "[]")
        d["preconditions"] = json.loads(d.get("preconditions") or "{}")
        d["reviewers"] = json.loads(d.get("reviewers") or "[]")
        d["is_negative_control"] = bool(d.get("is_negative_control", 0))
        results.append(d)
    return results


def save_benchmark_scorecard(scorecard_data: Any) -> str:
    """Persist a benchmark scorecard into lab_benchmarks table."""
    init_lab_tables()
    db = _get_db()
    import uuid

    if hasattr(scorecard_data, "to_dict"):
        data = scorecard_data.to_dict()
    else:
        data = dict(scorecard_data)

    benchmark_id = data.get("benchmark_id") or f"bench_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    protocol_version = data.get("protocol_version", "1.0.0")
    engine_id        = data.get("engine_id", "unknown")
    target_id        = data.get("target_id", "unknown")
    dataset_id       = data.get("dataset_id", "hexaguard_bench_core")
    dataset_version  = data.get("dataset_version", "1.0.0")
    execution_status = data.get("execution_status", "COMPLETED")
    benchmark_status = data.get("benchmark_status", "NOT_EVALUATED")
    status_reasons   = json.dumps(data.get("status_reasons", []))
    summary_counts   = json.dumps(data.get("counts", {}))
    metrics          = json.dumps(data.get("metrics", {}))
    critical_flags   = json.dumps(data.get("critical_review_flags", []))
    repeated_stats   = json.dumps(data.get("repeated_run_stats") or {})
    scorecard_json   = json.dumps(data)

    is_mysql = getattr(db, "_c", None) is not None or _USE_MYSQL
    if is_mysql:
        upsert_sql = """
            INSERT INTO lab_benchmarks (
                benchmark_id, protocol_version, engine_id, target_id, dataset_id,
                dataset_version, execution_status, benchmark_status, status_reasons,
                summary_counts, metrics, critical_review_flags, scorecard_json,
                repeated_run_stats, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            AS new_row
            ON DUPLICATE KEY UPDATE
                protocol_version      = new_row.protocol_version,
                engine_id             = new_row.engine_id,
                target_id             = new_row.target_id,
                dataset_id            = new_row.dataset_id,
                dataset_version       = new_row.dataset_version,
                execution_status      = new_row.execution_status,
                benchmark_status      = new_row.benchmark_status,
                status_reasons        = new_row.status_reasons,
                summary_counts        = new_row.summary_counts,
                metrics               = new_row.metrics,
                critical_review_flags = new_row.critical_review_flags,
                scorecard_json        = new_row.scorecard_json,
                repeated_run_stats    = new_row.repeated_run_stats,
                updated_at            = new_row.updated_at
        """
    else:
        upsert_sql = """
            INSERT INTO lab_benchmarks (
                benchmark_id, protocol_version, engine_id, target_id, dataset_id,
                dataset_version, execution_status, benchmark_status, status_reasons,
                summary_counts, metrics, critical_review_flags, scorecard_json,
                repeated_run_stats, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(benchmark_id) DO UPDATE SET
                protocol_version      = excluded.protocol_version,
                engine_id             = excluded.engine_id,
                target_id             = excluded.target_id,
                dataset_id            = excluded.dataset_id,
                dataset_version       = excluded.dataset_version,
                execution_status      = excluded.execution_status,
                benchmark_status      = excluded.benchmark_status,
                status_reasons        = excluded.status_reasons,
                summary_counts        = excluded.summary_counts,
                metrics               = excluded.metrics,
                critical_review_flags = excluded.critical_review_flags,
                scorecard_json        = excluded.scorecard_json,
                repeated_run_stats    = excluded.repeated_run_stats,
                updated_at            = excluded.updated_at
        """

    db.execute(upsert_sql, (
        benchmark_id, protocol_version, engine_id, target_id, dataset_id,
        dataset_version, execution_status, benchmark_status, status_reasons,
        summary_counts, metrics, critical_flags, scorecard_json,
        repeated_stats, now, now,
    ))
    db.commit()
    return benchmark_id


def get_benchmark_scorecard(benchmark_id: str) -> Optional[dict]:
    """Retrieve a benchmark scorecard by ID."""
    init_lab_tables()
    db = _get_db()
    row = db.execute("SELECT * FROM lab_benchmarks WHERE benchmark_id = ?", (benchmark_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["status_reasons"] = json.loads(d.get("status_reasons") or "[]")
    d["summary_counts"] = json.loads(d.get("summary_counts") or "{}")
    d["metrics"] = json.loads(d.get("metrics") or "{}")
    d["critical_review_flags"] = json.loads(d.get("critical_review_flags") or "[]")
    d["scorecard_json"] = json.loads(d.get("scorecard_json") or "{}")
    d["repeated_run_stats"] = json.loads(d.get("repeated_run_stats") or "{}")
    return d


def list_benchmark_scorecards(
    engine_id: Optional[str] = None,
    target_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """List recent benchmark scorecards."""
    init_lab_tables()
    db = _get_db()
    query = "SELECT * FROM lab_benchmarks"
    params: list[Any] = []
    clauses: list[str] = []

    if engine_id:
        clauses.append("engine_id = ?")
        params.append(engine_id)
    if target_id:
        clauses.append("target_id = ?")
        params.append(target_id)

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["status_reasons"] = json.loads(d.get("status_reasons") or "[]")
        d["summary_counts"] = json.loads(d.get("summary_counts") or "{}")
        d["metrics"] = json.loads(d.get("metrics") or "{}")
        d["critical_review_flags"] = json.loads(d.get("critical_review_flags") or "[]")
        d["repeated_run_stats"] = json.loads(d.get("repeated_run_stats") or "{}")
        results.append(d)
    return results
