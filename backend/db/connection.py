import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt

logger = logging.getLogger(__name__)

_os = os
_sys = sys

# ── Backend detection ─────────────────────────────────────────────────────────
# Set MYSQL_HOST (+ MYSQL_USER, MYSQL_PASS, MYSQL_DB) env vars to switch to
# MySQL (e.g. PythonAnywhere free MySQL).  Omit them to keep SQLite.
_MYSQL_HOST = _os.environ.get("MYSQL_HOST", "").strip()
_USE_MYSQL   = bool(_MYSQL_HOST)

if _USE_MYSQL:
    try:
        import pymysql
        import pymysql.cursors
        logger.info("database backend: MySQL @ %s", _MYSQL_HOST)
    except ImportError:
        logger.warning("pymysql not installed — falling back to SQLite")
        _USE_MYSQL = False


# ── Sentinel ──────────────────────────────────────────────────────────────────
_UNSET = object()

# ── Thread-local connections ──────────────────────────────────────────────────
_local = threading.local()


# ══════════════════════════════════════════════════════════════════════════════
#  MySQL adapter  — wraps pymysql connection with SQLite-compatible interface
# ══════════════════════════════════════════════════════════════════════════════

# Narrow SQL-prefix regex to translate SQLite 'CREATE [UNIQUE] INDEX IF NOT EXISTS' into MySQL 'CREATE [UNIQUE] INDEX'
_RE_MYSQL_INDEX_IF_NOT_EXISTS = re.compile(
    r"^(\s*(?:--[^\n]*\n\s*)*CREATE\s+(?:UNIQUE\s+)?INDEX)\s+IF\s+NOT\s+EXISTS\b",
    re.IGNORECASE,
)



class _MySQLAdapter:
    """Thin wrapper that makes a pymysql connection look like sqlite3.Connection."""

    def __init__(self, conn):
        self._c = conn
        self._in_transaction = False

    def _fix(self, sql: str) -> str:
        sql = sql.replace("?", "%s")
        if "AUTOINCREMENT" in sql:
            sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
            sql = sql.replace("AUTOINCREMENT", "AUTO_INCREMENT")
        if "INDEX" in sql.upper():
            sql = _RE_MYSQL_INDEX_IF_NOT_EXISTS.sub(r"\1", sql)
        return sql

    def _invalidate(self):
        """Reset transaction state and invalidate broken underlying connection."""
        self._in_transaction = False
        conn = self._c
        self._c = None
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        if getattr(_local, "mysql_conn", None) is conn:
            _local.mysql_conn = None

    def begin(self):
        """Explicitly begin a multi-statement transaction."""
        if self._in_transaction:
            raise sqlite3.OperationalError("cannot start a transaction within a transaction")
        if not self._c:
            raise sqlite3.OperationalError("cannot begin transaction on invalidated connection")
        try:
            self._c.begin()
            self._in_transaction = True
        except Exception as exc:
            self._invalidate()
            raise

    def execute(self, sql: str, params=()):
        if not self._c:
            raise sqlite3.OperationalError("cannot execute statement on invalidated connection")
        sql = self._fix(sql)
        cur = self._c.cursor()
        cur.execute(sql, params)
        if not self._in_transaction:
            try:
                self._c.commit()
            except Exception as exc:
                self._invalidate()
                raise
        return cur

    def executescript(self, sql: str):
        if not self._c:
            raise sqlite3.OperationalError("cannot execute script on invalidated connection")
        cur = self._c.cursor()
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            while stmt.startswith("--"):
                newline_idx = stmt.find("\n")
                if newline_idx == -1:
                    stmt = ""
                    break
                stmt = stmt[newline_idx + 1:].strip()
            if not stmt:
                continue
            stmt = self._fix(stmt)
            try:
                cur.execute(stmt)
            except Exception as exc:
                err_code = None
                if getattr(exc, "args", None) and len(exc.args) > 0:
                    try:
                        err_code = int(exc.args[0])
                    except (ValueError, TypeError):
                        err_code = None
                clean = stmt.upper()
                is_dup = (
                    (err_code == 1050 and bool(re.match(r"^CREATE\s+TABLE\b", clean)))
                    or (err_code == 1061 and bool(re.match(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\b", clean)))
                )
                if is_dup:
                    logger.debug("executescript stmt skipped (expected duplicate): %s | %s", stmt[:60], exc)
                else:
                    self._invalidate()
                    logger.error("executescript stmt failed: %s | %s", stmt[:80], exc)
                    raise
        if not self._in_transaction:
            try:
                self._c.commit()
            except Exception as exc:
                self._invalidate()
                raise

    def commit(self):
        if not self._c:
            self._in_transaction = False
            raise sqlite3.OperationalError("cannot commit invalidated connection")
        try:
            self._c.commit()
        except Exception as exc:
            self._invalidate()
            raise
        else:
            self._in_transaction = False

    def rollback(self):
        if not self._c:
            self._in_transaction = False
            raise sqlite3.OperationalError("cannot rollback invalidated connection")
        try:
            self._c.rollback()
        except Exception as exc:
            self._invalidate()
            raise
        else:
            self._in_transaction = False


def _make_mysql_conn():
    conn = pymysql.connect(
        host=_MYSQL_HOST,
        user=_os.environ.get("MYSQL_USER", ""),
        password=_os.environ.get("MYSQL_PASS", ""),
        database=_os.environ.get("MYSQL_DB", "securax"),
        port=int(_os.environ.get("MYSQL_PORT", "3306")),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        charset="utf8mb4",
        connect_timeout=10,
    )
    return conn


def _get_db():
    if _USE_MYSQL:
        conn = getattr(_local, "mysql_conn", None)
        if conn is None:
            conn = _make_mysql_conn()
            _local.mysql_conn = conn
        else:
            try:
                conn.ping(reconnect=True)
            except Exception:
                conn = _make_mysql_conn()
                _local.mysql_conn = conn
        return _MySQLAdapter(conn)

    # ── SQLite path (default) ─────────────────────────────────────────────────
    import sys as _sys
    req_path = _os.environ.get("DB_PATH") or getattr(_sys.modules.get("database"), "DB_PATH", None) or "securax.db"
    db_path = _resolve_db_path(req_path)
    if not getattr(_local, "conn", None) or getattr(_local, "conn_path", None) != db_path:
        if getattr(_local, "conn", None):
            try:
                _local.conn.close()
            except Exception:
                pass
        conn = sqlite3.connect(db_path, check_same_thread=True, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
        _local.conn_path = db_path
    return _local.conn


def _resolve_db_path(requested: str) -> str:
    backend_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    # If the default relative "securax.db" was given (or empty), anchor to backend/
    if not requested or requested == "securax.db":
        return _os.path.join(backend_dir, "securax.db")

    abs_path = _os.path.abspath(requested)
    parent = _os.path.dirname(abs_path)
    if parent:
        try:
            _os.makedirs(parent, exist_ok=True)
            return abs_path
        except OSError:
            pass
    fallback = _os.path.join(backend_dir, "securax.db")
    logger.warning(
        "DB path '%s' is not accessible — falling back to '%s'.",
        requested, fallback,
    )
    return fallback


DB_PATH = _resolve_db_path(_os.environ.get("DB_PATH", "securax.db"))


def _exec(sql: str, params: tuple = ()):
    db = _get_db()
    try:
        cur = db.execute(sql, params)
        db.commit()
        return cur
    except Exception as exc:
        db.rollback()
        logger.error("DB error | sql=%s | params=%s | err=%s", sql[:80], params, exc)
        raise


# ── Schema bootstrap ──────────────────────────────────────────────────────────

_SCHEMA_SQLITE = """
    CREATE TABLE IF NOT EXISTS users (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        username         TEXT    UNIQUE NOT NULL,
        email            TEXT,
        password_hash    TEXT    NOT NULL,
        role             TEXT    NOT NULL DEFAULT 'analyst',
        permissions      TEXT    NOT NULL DEFAULT '[]',
        is_active        INTEGER NOT NULL DEFAULT 1,
        totp_secret      TEXT,
        totp_enabled     INTEGER NOT NULL DEFAULT 0,
        failed_attempts  INTEGER NOT NULL DEFAULT 0,
        locked_until     TEXT,
        last_login       TEXT,
        login_count      INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT    NOT NULL,
        created_by       TEXT,
        locked_target    TEXT,
        api_token        TEXT,
        api_token_created TEXT,
        ai_data_sharing_opt_out INTEGER NOT NULL DEFAULT 0,
        ai_messages_used INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS scan_reports (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        token            TEXT    UNIQUE NOT NULL,
        user_id          INTEGER,
        username         TEXT,
        scan_type        TEXT,
        target           TEXT,
        risk_score       REAL    NOT NULL DEFAULT 0,
        vuln_count       INTEGER NOT NULL DEFAULT 0,
        critical_count   INTEGER NOT NULL DEFAULT 0,
        high_count       INTEGER NOT NULL DEFAULT 0,
        medium_count     INTEGER NOT NULL DEFAULT 0,
        low_count        INTEGER NOT NULL DEFAULT 0,
        result_json      TEXT    NOT NULL,
        original_content TEXT,
        stored_at        TEXT    NOT NULL,
        share_token      TEXT,
        share_expires_at TEXT,
        bounty_platform  TEXT,
        bounty_program_handle TEXT,
        bounty_asset     TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
    );
    CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id   INTEGER NOT NULL,
        check_name  TEXT    NOT NULL,
        severity    TEXT    NOT NULL,
        title       TEXT    NOT NULL,
        description TEXT,
        evidence    TEXT,
        remediation TEXT,
        line_number INTEGER NOT NULL DEFAULT 0,
        cve_ids     TEXT    NOT NULL DEFAULT '[]',
        is_fixed    INTEGER NOT NULL DEFAULT 0,
        fixed_at    TEXT,
        found_at    TEXT    NOT NULL,
        triage_status TEXT  NOT NULL DEFAULT 'New',
        triage_notes  TEXT,
        FOREIGN KEY (report_id) REFERENCES scan_reports(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        action       TEXT    NOT NULL,
        username     TEXT,
        user_id      INTEGER,
        category     TEXT    NOT NULL DEFAULT 'general',
        resource     TEXT,
        ip_address   TEXT,
        user_agent   TEXT,
        status       TEXT,
        details      TEXT,
        created_at   TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_users_username        ON users (username);
    CREATE INDEX IF NOT EXISTS idx_scan_reports_user     ON scan_reports (user_id, stored_at);
    CREATE INDEX IF NOT EXISTS idx_scan_reports_token    ON scan_reports (token);
    CREATE INDEX IF NOT EXISTS idx_scan_reports_stored   ON scan_reports (stored_at);
    CREATE INDEX IF NOT EXISTS idx_scan_reports_type     ON scan_reports (scan_type);
    CREATE INDEX IF NOT EXISTS idx_vulns_report          ON scan_vulnerabilities (report_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity        ON scan_vulnerabilities (severity, report_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_check           ON scan_vulnerabilities (check_name);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_user       ON audit_logs (user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs (action);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_category   ON audit_logs (category);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_time       ON audit_logs (created_at);
    CREATE TABLE IF NOT EXISTS scan_jobs (
        job_id        TEXT    PRIMARY KEY,
        scan_type     TEXT    NOT NULL,
        target        TEXT    NOT NULL,
        user_id       INTEGER NOT NULL,
        username      TEXT    NOT NULL,
        status        TEXT    NOT NULL DEFAULT 'queued',
        progress      INTEGER NOT NULL DEFAULT 0,
        message       TEXT    NOT NULL DEFAULT 'Queued…',
        result_json   TEXT,
        error         TEXT,
        report_token  TEXT,
        started_at    TEXT    NOT NULL,
        completed_at  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scan_jobs_user   ON scan_jobs (user_id, started_at);
    CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        username      TEXT    NOT NULL,
        scan_type     TEXT    NOT NULL,
        target        TEXT    NOT NULL,
        cron_expr     TEXT    NOT NULL DEFAULT 'daily',
        is_active     INTEGER NOT NULL DEFAULT 1,
        last_run_at   TEXT,
        next_run_at   TEXT,
        created_at    TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_scheduled_user   ON scheduled_scans (user_id);
    CREATE INDEX IF NOT EXISTS idx_scheduled_active ON scheduled_scans (is_active, next_run_at);
    CREATE TABLE IF NOT EXISTS subscriptions (
        user_id      INTEGER PRIMARY KEY,
        plan         TEXT    NOT NULL DEFAULT 'free',
        scans_used   INTEGER NOT NULL DEFAULT 0,
        cycle_start  TEXT    NOT NULL,
        expires_at   TEXT,
        notes        TEXT,
        created_at   TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_subs_plan ON subscriptions (plan);
    CREATE TABLE IF NOT EXISTS payments (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        payment_ref  TEXT    NOT NULL UNIQUE,
        user_id      INTEGER NOT NULL,
        plan         TEXT    NOT NULL,
        amount       REAL    NOT NULL,
        currency     TEXT    NOT NULL DEFAULT 'DZD',
        created_at   TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref);
    CREATE INDEX IF NOT EXISTS idx_payments_user ON payments (user_id);
    CREATE TABLE IF NOT EXISTS domain_verifications (
        user_id      INTEGER PRIMARY KEY,
        domain       TEXT    NOT NULL,
        verify_token TEXT    NOT NULL,
        verified     INTEGER NOT NULL DEFAULT 0,
        verified_at  TEXT,
        verified_by  TEXT,
        created_at   TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS network_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target      TEXT    NOT NULL,
        user_id     INTEGER NOT NULL,
        scan_time   TEXT    NOT NULL,
        hosts_json  TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nsnap_target ON network_snapshots (target, user_id);

    CREATE TABLE IF NOT EXISTS skill_ledger (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id           INTEGER NOT NULL,
        vuln_type         TEXT    NOT NULL,
        status            TEXT    NOT NULL DEFAULT 'theory_only',
        evidence_ref      TEXT,
        attempts_count    INTEGER NOT NULL DEFAULT 0,
        last_practiced_at TEXT,
        created_at        TEXT    NOT NULL,
        updated_at        TEXT    NOT NULL,
        UNIQUE(user_id, vuln_type),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_skill_ledger_user ON skill_ledger (user_id);
    CREATE INDEX IF NOT EXISTS idx_skill_ledger_vuln ON skill_ledger (user_id, vuln_type);

    CREATE TABLE IF NOT EXISTS shadow_manual_tasks (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        report_token      TEXT    NOT NULL,
        user_id           INTEGER,
        vuln_type         TEXT    NOT NULL,
        status            TEXT    NOT NULL DEFAULT 'pending',
        notes             TEXT,
        created_at        TEXT    NOT NULL,
        updated_at        TEXT,
        UNIQUE(report_token, vuln_type),
        FOREIGN KEY (report_token) REFERENCES scan_reports(token) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_shadow_tasks_token ON shadow_manual_tasks (report_token);
    CREATE INDEX IF NOT EXISTS idx_shadow_tasks_user  ON shadow_manual_tasks (user_id, status);

    CREATE TABLE IF NOT EXISTS dojo_completions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        date_key     TEXT    NOT NULL,
        vuln_type    TEXT    NOT NULL,
        completed_at TEXT    NOT NULL,
        UNIQUE(user_id, date_key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_dojo_user_date ON dojo_completions (user_id, date_key);

    CREATE TABLE IF NOT EXISTS learning_exercises (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_type       TEXT NOT NULL,
        capability      TEXT NOT NULL,
        exercise_type   TEXT NOT NULL,
        title_en        TEXT NOT NULL,
        description_en  TEXT,
        difficulty      TEXT NOT NULL DEFAULT 'medium',
        content_json    TEXT,
        cert_hint       TEXT,
        is_active       INTEGER NOT NULL DEFAULT 1,
        created_at      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_exercises_vuln_cap ON learning_exercises (vuln_type, capability);

    CREATE TABLE IF NOT EXISTS exercise_attempts (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id               INTEGER NOT NULL,
        exercise_id           INTEGER NOT NULL,
        vuln_type             TEXT NOT NULL,
        capability            TEXT NOT NULL,
        attempt_number        INTEGER NOT NULL DEFAULT 1,
        started_at            TEXT NOT NULL,
        completed_at          TEXT,
        submission_text       TEXT,
        score                 REAL,
        hints_used            INTEGER NOT NULL DEFAULT 0,
        aria_calls_used       INTEGER NOT NULL DEFAULT 0,
        solution_viewed       INTEGER NOT NULL DEFAULT 0,
        result                TEXT NOT NULL DEFAULT 'pending',
        evaluation_status     TEXT NOT NULL DEFAULT 'pending',
        evidence_id           INTEGER,
        FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (exercise_id) REFERENCES learning_exercises(id)
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_user_vuln ON exercise_attempts (user_id, vuln_type);
    CREATE INDEX IF NOT EXISTS idx_attempts_user_cap  ON exercise_attempts (user_id, vuln_type, capability);

    CREATE TABLE IF NOT EXISTS skill_capability_evidence (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id         INTEGER NOT NULL,
        vuln_type       TEXT NOT NULL,
        capability      TEXT NOT NULL,
        evidence_type   TEXT NOT NULL,
        evidence_source TEXT NOT NULL,
        source_id       TEXT,
        is_verified     INTEGER NOT NULL DEFAULT 0,
        score           REAL,
        notes           TEXT,
        created_at      TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE (user_id, vuln_type, capability, evidence_source)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uidx_sce_user_cap_src ON skill_capability_evidence (user_id, vuln_type, capability, evidence_source);
    CREATE INDEX IF NOT EXISTS idx_sce_user_vuln ON skill_capability_evidence (user_id, vuln_type);
    CREATE INDEX IF NOT EXISTS idx_sce_user_cap  ON skill_capability_evidence (user_id, vuln_type, capability);
    CREATE INDEX IF NOT EXISTS idx_sce_verified  ON skill_capability_evidence (user_id, is_verified);

    CREATE TABLE IF NOT EXISTS active_sandboxes (
        id               TEXT    PRIMARY KEY,
        user_id          INTEGER NOT NULL,
        vuln_type        TEXT    NOT NULL,
        name             TEXT,
        image            TEXT,
        host_port        INTEGER,
        container_id     TEXT,
        status           TEXT    NOT NULL DEFAULT 'running',
        completed        INTEGER NOT NULL DEFAULT 0,
        flag_hash        TEXT    NOT NULL,
        started_at       TEXT    NOT NULL,
        expires_at       REAL    NOT NULL,
        timeout_seconds  INTEGER NOT NULL,
        created_at       TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_active_sandboxes_user ON active_sandboxes (user_id, status);

    -- PhD Tracker: user-added and saved opportunity records (persists across restarts)
    CREATE TABLE IF NOT EXISTS phd_opportunities (
        id               TEXT    PRIMARY KEY,
        user_id          INTEGER NOT NULL,
        source_type      TEXT    NOT NULL DEFAULT 'user_added',
        source_file      TEXT,
        discovery_source TEXT,
        institution      TEXT,
        country          TEXT,
        program          TEXT,
        field            TEXT,
        funding          TEXT,
        deadline         TEXT,
        deadline_note    TEXT,
        days_remaining   INTEGER,
        deadline_status  TEXT    NOT NULL DEFAULT 'unknown',
        status           TEXT    NOT NULL DEFAULT 'researching',
        status_ar        TEXT,
        priority         TEXT    NOT NULL DEFAULT 'medium',
        priority_ar      TEXT,
        notes            TEXT,
        contact          TEXT,
        verified         TEXT,
        supervisor       TEXT,
        lab_url          TEXT,
        application_url  TEXT,
        funding_type     TEXT,
        stipend_info     TEXT,
        language_req     TEXT,
        eligibility_note TEXT,
        raw_source_ref   TEXT,
        record_type      TEXT NOT NULL DEFAULT 'tracked_opportunity',
        verification_status TEXT NOT NULL DEFAULT 'unconfirmed',
        added_at         TEXT    NOT NULL,
        updated_at       TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_phd_opps_user   ON phd_opportunities (user_id, status);
    CREATE INDEX IF NOT EXISTS idx_phd_opps_source ON phd_opportunities (source_type, user_id);
    CREATE INDEX IF NOT EXISTS idx_phd_opps_country ON phd_opportunities (user_id, country);

    -- PhD Live Discovery: results from external source adapters
    CREATE TABLE IF NOT EXISTS phd_discovery_cache (
        id               TEXT    PRIMARY KEY,
        source_id        TEXT    NOT NULL,
        source_name      TEXT    NOT NULL,
        fetch_timestamp  TEXT    NOT NULL,
        institution      TEXT,
        country          TEXT,
        program          TEXT,
        field_keywords   TEXT,
        funding_type     TEXT,
        stipend_info     TEXT,
        deadline_raw     TEXT,
        deadline_parsed  TEXT,
        deadline_status  TEXT    NOT NULL DEFAULT 'unknown',
        supervisor       TEXT,
        lab_url          TEXT,
        application_url  TEXT,
        language_req     TEXT,
        eligibility_intl INTEGER NOT NULL DEFAULT -1,
        confidence       REAL    DEFAULT NULL,
        raw_json         TEXT,
        is_stale         INTEGER NOT NULL DEFAULT 0,
        last_verified    TEXT,
        saved_opp_id     TEXT,
        record_type      TEXT NOT NULL DEFAULT 'verified_vacancy',
        verification_status TEXT NOT NULL DEFAULT 'unconfirmed'
    );
    CREATE INDEX IF NOT EXISTS idx_phd_disc_source   ON phd_discovery_cache (source_id, fetch_timestamp);
    CREATE INDEX IF NOT EXISTS idx_phd_disc_country  ON phd_discovery_cache (country);
    CREATE INDEX IF NOT EXISTS idx_phd_disc_stale    ON phd_discovery_cache (is_stale, fetch_timestamp);

    -- PhD Discovery source health tracking (Gate 1.7 Transparency Registry)
    CREATE TABLE IF NOT EXISTS phd_source_health (
        source_id        TEXT    PRIMARY KEY,
        source_name      TEXT    NOT NULL,
        source_url       TEXT,
        source_type      TEXT    NOT NULL DEFAULT 'official_vacancy_portal',
        access_method    TEXT    NOT NULL DEFAULT 'API',
        last_fetch_at    TEXT,
        last_success_at  TEXT,
        last_error       TEXT,
        last_http_status INTEGER,
        fetch_count      INTEGER NOT NULL DEFAULT 0,
        error_count      INTEGER NOT NULL DEFAULT 0,
        result_count     INTEGER NOT NULL DEFAULT 0,
        raw_count        INTEGER NOT NULL DEFAULT 0,
        accepted_count   INTEGER NOT NULL DEFAULT 0,
        rejected_count   INTEGER NOT NULL DEFAULT 0,
        last_error_category TEXT,
        next_action      TEXT,
        enabled          INTEGER NOT NULL DEFAULT 1,
        status           TEXT    NOT NULL DEFAULT 'unknown'
    );

    -- Gate 1.7: PhD Workbook Deduplication & Import Audit Trail
    CREATE TABLE IF NOT EXISTS phd_dedup_audit (
        id                       TEXT PRIMARY KEY,
        run_timestamp            TEXT NOT NULL,
        raw_count                INTEGER NOT NULL,
        unique_count             INTEGER NOT NULL,
        exact_duplicates_merged  INTEGER NOT NULL,
        fuzzy_duplicates_flagged INTEGER NOT NULL,
        backup_file              TEXT,
        audit_summary            TEXT NOT NULL,
        created_at               TEXT NOT NULL
    );

    -- Gate 1.6: Supervisor Briefing Packs & Private Sharing
    CREATE TABLE IF NOT EXISTS supervisor_briefings (
        id                   TEXT PRIMARY KEY,
        user_id              INTEGER NOT NULL,
        opportunity_id       TEXT,
        title                TEXT NOT NULL,
        target_supervisor    TEXT,
        share_token          TEXT UNIQUE,
        is_shared            INTEGER NOT NULL DEFAULT 0,
        is_revoked           INTEGER NOT NULL DEFAULT 0,
        expires_at           TEXT,
        allowed_evidence_ids TEXT,
        allowed_document_ids TEXT,
        custom_statement     TEXT,
        briefing_payload     TEXT,
        access_count         INTEGER NOT NULL DEFAULT 0,
        last_accessed_at     TEXT,
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_briefings_user  ON supervisor_briefings (user_id);
    CREATE INDEX IF NOT EXISTS idx_briefings_token ON supervisor_briefings (share_token);

    -- Gate 1.6: Proof-of-Work Evidence Registry
    CREATE TABLE IF NOT EXISTS proof_of_work_artifacts (
        id                   TEXT PRIMARY KEY,
        user_id              INTEGER,
        category             TEXT NOT NULL,
        title                TEXT NOT NULL,
        description          TEXT NOT NULL,
        originating_module   TEXT NOT NULL,
        repo_path            TEXT,
        commit_hash          TEXT,
        reproducible_cmd     TEXT,
        actual_result        TEXT,
        limitations          TEXT,
        integrity_hash       TEXT,
        verification_method  TEXT NOT NULL,
        status               TEXT NOT NULL DEFAULT 'VERIFIED',
        verified_at          TEXT,
        is_public_eligible   INTEGER NOT NULL DEFAULT 1,
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_pow_category ON proof_of_work_artifacts (category);
    CREATE INDEX IF NOT EXISTS idx_pow_status   ON proof_of_work_artifacts (status);
"""

_SCHEMA_MYSQL = """
    CREATE TABLE IF NOT EXISTS users (
        id               INT          AUTO_INCREMENT PRIMARY KEY,
        username         VARCHAR(150) UNIQUE NOT NULL,
        email            VARCHAR(255),
        password_hash    TEXT         NOT NULL,
        role             VARCHAR(50)  NOT NULL DEFAULT 'analyst',
        permissions      TEXT         NOT NULL,
        is_active        TINYINT(1)   NOT NULL DEFAULT 1,
        totp_secret      TEXT,
        totp_enabled     TINYINT(1)   NOT NULL DEFAULT 0,
        failed_attempts  INT          NOT NULL DEFAULT 0,
        locked_until     VARCHAR(50),
        last_login       VARCHAR(50),
        login_count      INT          NOT NULL DEFAULT 0,
        created_at       VARCHAR(50)  NOT NULL,
        created_by       VARCHAR(150),
        locked_target    VARCHAR(255),
        api_token        VARCHAR(255),
        api_token_created VARCHAR(50),
        must_change_password TINYINT(1) NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS scan_reports (
        id               INT          AUTO_INCREMENT PRIMARY KEY,
        token            VARCHAR(64)  UNIQUE NOT NULL,
        user_id          INT,
        username         VARCHAR(150),
        scan_type        VARCHAR(50),
        target           VARCHAR(500),
        risk_score       FLOAT        NOT NULL DEFAULT 0,
        vuln_count       INT          NOT NULL DEFAULT 0,
        critical_count   INT          NOT NULL DEFAULT 0,
        high_count       INT          NOT NULL DEFAULT 0,
        medium_count     INT          NOT NULL DEFAULT 0,
        low_count        INT          NOT NULL DEFAULT 0,
        result_json      MEDIUMTEXT   NOT NULL,
        original_content MEDIUMTEXT,
        stored_at        VARCHAR(50)  NOT NULL,
        bounty_platform       VARCHAR(100),
        bounty_program_handle VARCHAR(150),
        bounty_asset          VARCHAR(255),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
        id          INT          AUTO_INCREMENT PRIMARY KEY,
        report_id   INT          NOT NULL,
        check_name  VARCHAR(255) NOT NULL,
        severity    VARCHAR(20)  NOT NULL,
        title       VARCHAR(500) NOT NULL,
        description TEXT,
        evidence    TEXT,
        remediation TEXT,
        line_number INT          NOT NULL DEFAULT 0,
        cve_ids     TEXT         NOT NULL,
        is_fixed    TINYINT(1)   NOT NULL DEFAULT 0,
        fixed_at    VARCHAR(50),
        found_at    VARCHAR(50)  NOT NULL,
        triage_status VARCHAR(50) NOT NULL DEFAULT 'New',
        triage_notes  TEXT,
        FOREIGN KEY (report_id) REFERENCES scan_reports(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS audit_logs (
        id           INT          AUTO_INCREMENT PRIMARY KEY,
        action       VARCHAR(100) NOT NULL,
        username     VARCHAR(150),
        user_id      INT,
        category     VARCHAR(50)  NOT NULL DEFAULT 'general',
        resource     VARCHAR(500),
        ip_address   VARCHAR(45),
        user_agent   TEXT,
        status       VARCHAR(50),
        details      TEXT,
        created_at   VARCHAR(50)  NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE INDEX IF NOT EXISTS idx_users_username     ON users (username);
    CREATE INDEX IF NOT EXISTS idx_reports_user       ON scan_reports (user_id, stored_at);
    CREATE INDEX IF NOT EXISTS idx_reports_token      ON scan_reports (token);
    CREATE INDEX IF NOT EXISTS idx_reports_stored     ON scan_reports (stored_at);
    CREATE INDEX IF NOT EXISTS idx_reports_type       ON scan_reports (scan_type);
    CREATE INDEX IF NOT EXISTS idx_vulns_report       ON scan_vulnerabilities (report_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity     ON scan_vulnerabilities (severity);
    CREATE INDEX IF NOT EXISTS idx_vulns_check        ON scan_vulnerabilities (check_name);
    CREATE INDEX IF NOT EXISTS idx_audit_user         ON audit_logs (user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_action       ON audit_logs (action);
    CREATE INDEX IF NOT EXISTS idx_audit_time         ON audit_logs (created_at);
    CREATE TABLE IF NOT EXISTS scan_jobs (
        job_id        VARCHAR(36)  PRIMARY KEY,
        scan_type     VARCHAR(50)  NOT NULL,
        target        VARCHAR(500) NOT NULL,
        user_id       INT          NOT NULL,
        username      VARCHAR(150) NOT NULL,
        status        VARCHAR(20)  NOT NULL DEFAULT 'queued',
        progress      INT          NOT NULL DEFAULT 0,
        message       TEXT         NOT NULL,
        result_json   MEDIUMTEXT,
        error         TEXT,
        report_token  VARCHAR(64),
        started_at    VARCHAR(50)  NOT NULL,
        completed_at  VARCHAR(50)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_jobs_user   ON scan_jobs (user_id, started_at);
    CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs (status);
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id            INT          AUTO_INCREMENT PRIMARY KEY,
        user_id       INT          NOT NULL,
        username      VARCHAR(150) NOT NULL,
        scan_type     VARCHAR(50)  NOT NULL,
        target        VARCHAR(500) NOT NULL,
        cron_expr     VARCHAR(50)  NOT NULL DEFAULT 'daily',
        is_active     TINYINT(1)   NOT NULL DEFAULT 1,
        last_run_at   VARCHAR(50),
        next_run_at   VARCHAR(50),
        created_at    VARCHAR(50)  NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_sched_user   ON scheduled_scans (user_id);
    CREATE INDEX IF NOT EXISTS idx_sched_active ON scheduled_scans (is_active, next_run_at);
    CREATE TABLE IF NOT EXISTS subscriptions (
        user_id      INT         PRIMARY KEY,
        plan         VARCHAR(30) NOT NULL DEFAULT 'free',
        scans_used   INT         NOT NULL DEFAULT 0,
        cycle_start  VARCHAR(50) NOT NULL,
        expires_at   VARCHAR(50),
        notes        TEXT,
        created_at   VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE TABLE IF NOT EXISTS domain_verifications (
        user_id      INT          PRIMARY KEY,
        domain       VARCHAR(255) NOT NULL,
        verify_token VARCHAR(64)  NOT NULL,
        verified     TINYINT(1)   NOT NULL DEFAULT 0,
        verified_at  VARCHAR(50),
        verified_by  VARCHAR(150),
        created_at   VARCHAR(50)  NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE TABLE IF NOT EXISTS network_snapshots (
        id          INT          AUTO_INCREMENT PRIMARY KEY,
        target      VARCHAR(500) NOT NULL,
        user_id     INT          NOT NULL,
        scan_time   VARCHAR(50)  NOT NULL,
        hosts_json  MEDIUMTEXT   NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS skill_ledger (
        id                INT          AUTO_INCREMENT PRIMARY KEY,
        user_id           INT          NOT NULL,
        vuln_type         VARCHAR(100) NOT NULL,
        status            VARCHAR(50)  NOT NULL DEFAULT 'theory_only',
        evidence_ref      TEXT,
        attempts_count    INT          NOT NULL DEFAULT 0,
        last_practiced_at VARCHAR(50),
        created_at        VARCHAR(50)  NOT NULL,
        updated_at        VARCHAR(50)  NOT NULL,
        UNIQUE KEY uq_user_vuln (user_id, vuln_type),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_skill_ledger_user ON skill_ledger (user_id);

    CREATE TABLE IF NOT EXISTS shadow_manual_tasks (
        id                INT          AUTO_INCREMENT PRIMARY KEY,
        report_token      VARCHAR(64)  NOT NULL,
        user_id           INT,
        vuln_type         VARCHAR(100) NOT NULL,
        status            VARCHAR(50)  NOT NULL DEFAULT 'pending',
        notes             TEXT,
        created_at        VARCHAR(50)  NOT NULL,
        updated_at        VARCHAR(50),
        UNIQUE KEY uq_report_vuln (report_token, vuln_type),
        FOREIGN KEY (report_token) REFERENCES scan_reports(token) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_shadow_tasks_token ON shadow_manual_tasks (report_token);

    CREATE TABLE IF NOT EXISTS dojo_completions (
        id           INT          AUTO_INCREMENT PRIMARY KEY,
        user_id      INT          NOT NULL,
        date_key     VARCHAR(20)  NOT NULL,
        vuln_type    VARCHAR(100) NOT NULL,
        completed_at VARCHAR(50)  NOT NULL,
        UNIQUE KEY uq_dojo_user_date (user_id, date_key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS learning_exercises (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        vuln_type       VARCHAR(100) NOT NULL,
        capability      VARCHAR(50)  NOT NULL,
        exercise_type   VARCHAR(50)  NOT NULL,
        title_en        VARCHAR(255) NOT NULL,
        description_en  TEXT,
        difficulty      VARCHAR(50)  NOT NULL DEFAULT 'medium',
        content_json    MEDIUMTEXT,
        cert_hint       TEXT,
        is_active       TINYINT(1)   NOT NULL DEFAULT 1,
        created_at      VARCHAR(50)  NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_exercises_vuln_cap ON learning_exercises (vuln_type, capability);

    CREATE TABLE IF NOT EXISTS exercise_attempts (
        id                    INT AUTO_INCREMENT PRIMARY KEY,
        user_id               INT          NOT NULL,
        exercise_id           INT          NOT NULL,
        vuln_type             VARCHAR(100) NOT NULL,
        capability            VARCHAR(50)  NOT NULL,
        attempt_number        INT          NOT NULL DEFAULT 1,
        started_at            VARCHAR(50)  NOT NULL,
        completed_at          VARCHAR(50),
        submission_text       MEDIUMTEXT,
        score                 FLOAT,
        hints_used            INT          NOT NULL DEFAULT 0,
        aria_calls_used       INT          NOT NULL DEFAULT 0,
        solution_viewed       TINYINT(1)   NOT NULL DEFAULT 0,
        result                VARCHAR(50)  NOT NULL DEFAULT 'pending',
        evaluation_status     VARCHAR(50)  NOT NULL DEFAULT 'pending',
        evidence_id           INT,
        FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (exercise_id) REFERENCES learning_exercises(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_attempts_user_vuln ON exercise_attempts (user_id, vuln_type);
    CREATE INDEX IF NOT EXISTS idx_attempts_user_cap  ON exercise_attempts (user_id, vuln_type, capability);

    CREATE TABLE IF NOT EXISTS skill_capability_evidence (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        user_id         INT          NOT NULL,
        vuln_type       VARCHAR(100) NOT NULL,
        capability      VARCHAR(50)  NOT NULL,
        evidence_type   VARCHAR(50)  NOT NULL,
        evidence_source VARCHAR(255) NOT NULL,
        source_id       VARCHAR(255),
        is_verified     TINYINT(1)   NOT NULL DEFAULT 0,
        score           FLOAT,
        notes           TEXT,
        created_at      VARCHAR(50)  NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uidx_sce_user_cap_src (user_id, vuln_type, capability, evidence_source)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_sce_user_vuln ON skill_capability_evidence (user_id, vuln_type);
    CREATE INDEX IF NOT EXISTS idx_sce_user_cap  ON skill_capability_evidence (user_id, vuln_type, capability);
    CREATE INDEX IF NOT EXISTS idx_sce_verified  ON skill_capability_evidence (user_id, is_verified);

    CREATE TABLE IF NOT EXISTS active_sandboxes (
        id               VARCHAR(64)  PRIMARY KEY,
        user_id          INT          NOT NULL,
        vuln_type        VARCHAR(100) NOT NULL,
        name             VARCHAR(255),
        image            VARCHAR(255),
        host_port        INT,
        container_id     VARCHAR(64),
        status           VARCHAR(50)  NOT NULL DEFAULT 'running',
        completed        TINYINT(1)   NOT NULL DEFAULT 0,
        flag_hash        VARCHAR(128) NOT NULL,
        started_at       VARCHAR(50)  NOT NULL,
        expires_at       DOUBLE       NOT NULL,
        timeout_seconds  INT          NOT NULL,
        created_at       VARCHAR(50)  NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_active_sandboxes_user ON active_sandboxes (user_id, status);

    CREATE TABLE IF NOT EXISTS supervisor_briefings (
        id                   VARCHAR(64) PRIMARY KEY,
        user_id              INT NOT NULL,
        opportunity_id       VARCHAR(64),
        title                VARCHAR(255) NOT NULL,
        target_supervisor    VARCHAR(255),
        share_token          VARCHAR(128) UNIQUE,
        is_shared            TINYINT(1) NOT NULL DEFAULT 0,
        is_revoked           TINYINT(1) NOT NULL DEFAULT 0,
        expires_at           VARCHAR(50),
        allowed_evidence_ids MEDIUMTEXT,
        allowed_document_ids MEDIUMTEXT,
        custom_statement     TEXT,
        briefing_payload     MEDIUMTEXT,
        access_count         INT NOT NULL DEFAULT 0,
        last_accessed_at     VARCHAR(50),
        created_at           VARCHAR(50) NOT NULL,
        updated_at           VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_briefings_user  ON supervisor_briefings (user_id);
    CREATE INDEX IF NOT EXISTS idx_briefings_token ON supervisor_briefings (share_token);

    CREATE TABLE IF NOT EXISTS proof_of_work_artifacts (
        id                   VARCHAR(64) PRIMARY KEY,
        user_id              INT,
        category             VARCHAR(50) NOT NULL,
        title                VARCHAR(255) NOT NULL,
        description          TEXT NOT NULL,
        originating_module   VARCHAR(255) NOT NULL,
        repo_path            VARCHAR(255),
        commit_hash          VARCHAR(64),
        reproducible_cmd     TEXT,
        actual_result        TEXT,
        limitations          TEXT,
        integrity_hash       VARCHAR(128),
        verification_method  VARCHAR(255) NOT NULL,
        status               VARCHAR(50) NOT NULL DEFAULT 'VERIFIED',
        verified_at          VARCHAR(50),
        is_public_eligible   TINYINT(1) NOT NULL DEFAULT 1,
        created_at           VARCHAR(50) NOT NULL,
        updated_at           VARCHAR(50) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_pow_category ON proof_of_work_artifacts (category);
    CREATE INDEX IF NOT EXISTS idx_pow_status   ON proof_of_work_artifacts (status);

    CREATE TABLE IF NOT EXISTS phd_opportunities (
        id                  VARCHAR(64) PRIMARY KEY,
        user_id             INT NOT NULL,
        source_type         VARCHAR(64) NOT NULL DEFAULT 'user_added',
        source_file         VARCHAR(255),
        discovery_source    VARCHAR(255),
        institution         VARCHAR(255),
        country             VARCHAR(100),
        program             VARCHAR(255),
        field               VARCHAR(255),
        funding             VARCHAR(100),
        deadline            VARCHAR(50),
        deadline_note       TEXT,
        days_remaining      INT,
        deadline_status     VARCHAR(50) NOT NULL DEFAULT 'unknown',
        status              VARCHAR(50) NOT NULL DEFAULT 'researching',
        status_ar           VARCHAR(100),
        priority            VARCHAR(50) NOT NULL DEFAULT 'medium',
        priority_ar         VARCHAR(100),
        notes               TEXT,
        contact             TEXT,
        verified            VARCHAR(50),
        supervisor          VARCHAR(255),
        lab_url             VARCHAR(500),
        application_url     VARCHAR(500),
        funding_type        VARCHAR(100),
        stipend_info        TEXT,
        language_req        VARCHAR(255),
        eligibility_note    TEXT,
        raw_source_ref      TEXT,
        record_type         VARCHAR(64) NOT NULL DEFAULT 'tracked_opportunity',
        verification_status VARCHAR(64) NOT NULL DEFAULT 'unconfirmed',
        added_at            VARCHAR(50) NOT NULL,
        updated_at          VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_phd_opps_user    ON phd_opportunities (user_id, status);
    CREATE INDEX IF NOT EXISTS idx_phd_opps_source  ON phd_opportunities (source_type, user_id);
    CREATE INDEX IF NOT EXISTS idx_phd_opps_country ON phd_opportunities (user_id, country);

    CREATE TABLE IF NOT EXISTS phd_discovery_cache (
        id                  VARCHAR(64) PRIMARY KEY,
        source_id           VARCHAR(64) NOT NULL,
        source_name         VARCHAR(255) NOT NULL,
        fetch_timestamp     VARCHAR(50) NOT NULL,
        institution         VARCHAR(255),
        country             VARCHAR(100),
        program             VARCHAR(255),
        field_keywords      TEXT,
        funding_type        VARCHAR(100),
        stipend_info        TEXT,
        deadline_raw        VARCHAR(100),
        deadline_parsed     VARCHAR(50),
        deadline_status     VARCHAR(50) NOT NULL DEFAULT 'unknown',
        supervisor          VARCHAR(255),
        lab_url             VARCHAR(500),
        application_url     VARCHAR(500),
        language_req        VARCHAR(255),
        eligibility_intl    INT NOT NULL DEFAULT -1,
        confidence          FLOAT DEFAULT NULL,
        raw_json            MEDIUMTEXT,
        is_stale            TINYINT(1) NOT NULL DEFAULT 0,
        last_verified       VARCHAR(50),
        saved_opp_id        VARCHAR(64),
        record_type         VARCHAR(64) NOT NULL DEFAULT 'verified_vacancy',
        verification_status VARCHAR(64) NOT NULL DEFAULT 'unconfirmed'
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE INDEX IF NOT EXISTS idx_phd_disc_source   ON phd_discovery_cache (source_id, fetch_timestamp);
    CREATE INDEX IF NOT EXISTS idx_phd_disc_country  ON phd_discovery_cache (country);
    CREATE INDEX IF NOT EXISTS idx_phd_disc_stale    ON phd_discovery_cache (is_stale, fetch_timestamp);

    CREATE TABLE IF NOT EXISTS phd_source_health (
        source_id           VARCHAR(64) PRIMARY KEY,
        source_name         VARCHAR(255) NOT NULL,
        source_url          VARCHAR(500),
        source_type         VARCHAR(64) NOT NULL DEFAULT 'official_vacancy_portal',
        access_method       VARCHAR(64) NOT NULL DEFAULT 'API',
        last_fetch_at       VARCHAR(50),
        last_success_at     VARCHAR(50),
        last_error          TEXT,
        last_http_status    INT,
        fetch_count         INT NOT NULL DEFAULT 0,
        error_count         INT NOT NULL DEFAULT 0,
        result_count        INT NOT NULL DEFAULT 0,
        raw_count           INT NOT NULL DEFAULT 0,
        accepted_count      INT NOT NULL DEFAULT 0,
        rejected_count      INT NOT NULL DEFAULT 0,
        last_error_category VARCHAR(100),
        next_action         TEXT,
        enabled             TINYINT(1) NOT NULL DEFAULT 1,
        status              VARCHAR(50) NOT NULL DEFAULT 'unknown'
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS payments (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        payment_ref  VARCHAR(128) NOT NULL UNIQUE,
        user_id      INT NOT NULL,
        plan         VARCHAR(64) NOT NULL,
        amount       DECIMAL(10, 2) NOT NULL,
        currency     VARCHAR(10) NOT NULL DEFAULT 'DZD',
        created_at   VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref);
    CREATE INDEX IF NOT EXISTS idx_payments_user       ON payments (user_id);
"""


# ── Lab Index Allowlist & Safe Creation ──────────────────────────────────────
LAB_INDEX_ALLOWLIST = {
    ("lab_targets", "idx_lab_targets_kind"): ("kind",),
    ("lab_targets", "idx_lab_targets_enabled"): ("enabled",),
    ("lab_ground_truth", "idx_lab_gt_dataset"): ("dataset_id", "dataset_version"),
    ("lab_ground_truth", "idx_lab_gt_target"): ("target_id",),
    ("lab_ground_truth", "idx_lab_gt_split"): ("split",),
    ("lab_benchmarks", "idx_lab_bench_engine"): ("engine_id",),
    ("lab_benchmarks", "idx_lab_bench_target"): ("target_id",),
    ("lab_benchmarks", "idx_lab_bench_status"): ("benchmark_status",),
}


def _extract_count(row, col_name: str = "total_count") -> int:
    """Safely extract integer count from a query row across sqlite3.Row, tuple, and DictCursor."""
    if not row:
        return 0
    if isinstance(row, dict):
        val = row.get(col_name)
        if val is None and len(row) > 0:
            val = next(iter(row.values()))
        return int(val or 0)
    try:
        return int(row[col_name])
    except (TypeError, IndexError, KeyError):
        return int(row[0])


def create_lab_index_if_not_exists(table: str, index_name: str, db=None) -> None:
    """Ensure a lab index exists safely on either SQLite or MySQL.

    Uses an explicit allowlist to prevent arbitrary DDL, accepts the active
    database connection to preserve initialization context, and catches only
    PyMySQL error 1061 (ER_DUP_KEYNAME) for concurrent creation races.
    """
    key = (table, index_name)
    if key not in LAB_INDEX_ALLOWLIST:
        raise ValueError(f"Index {index_name} on {table} is not permitted by LAB_INDEX_ALLOWLIST")

    columns = LAB_INDEX_ALLOWLIST[key]
    if db is None:
        db = _get_db()

    is_mysql = getattr(db, "_c", None) is not None or _USE_MYSQL

    if is_mysql:
        try:
            import pymysql
            pymysql_op_err = pymysql.err.OperationalError
        except ImportError:
            pymysql_op_err = None

        cur = db.execute(
            "SELECT 1 FROM information_schema.statistics "
            "WHERE table_schema = DATABASE() AND table_name = %s AND index_name = %s LIMIT 1",
            (table, index_name),
        )
        if cur.fetchone():
            return

        cols_clause = ", ".join(f"`{c}`" for c in columns)
        try:
            db.execute(f"CREATE INDEX `{index_name}` ON `{table}` ({cols_clause})")
            db.commit()
        except Exception as exc:
            if pymysql_op_err and isinstance(exc, pymysql_op_err) and exc.args and exc.args[0] == 1061:
                logger.debug("Index %s on %s created concurrently by another worker", index_name, table)
            elif exc.args and exc.args[0] == 1061:
                logger.debug("Index %s on %s created concurrently by another worker", index_name, table)
            else:
                raise
    else:
        cols_clause = ", ".join(columns)
        db.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({cols_clause})")
        db.commit()


def _is_expected_migration_duplicate(exc: Exception, statement: str, is_mysql: bool) -> bool:
    """Determine if a migration execution error is an expected, safe idempotent duplicate.

    Distinguishes by database engine (SQLite vs MySQL) and by query context:
    - ALTER TABLE ... ADD COLUMN:
        * SQLite: sqlite3.OperationalError with 'duplicate column name'
        * MySQL: PyMySQL error code 1060 (ER_DUP_FIELDNAME)
    - CREATE TABLE:
        * SQLite: Natively handled by IF NOT EXISTS; any error is unexpected and returns False
        * MySQL: Error code 1050 (ER_TABLE_EXISTS_ERROR)
    - CREATE INDEX:
        * SQLite: Natively handled by IF NOT EXISTS; any error is unexpected and returns False
        * MySQL: Error code 1061 (ER_DUP_KEYNAME)

    Re-raises (returns False) for any other error including syntax errors, missing tables,
    locked databases, disk I/O errors, or mismatched error codes.
    """
    clean_stmt = statement.strip()
    while clean_stmt.startswith("--"):
        newline_idx = clean_stmt.find("\n")
        if newline_idx == -1:
            return False
        clean_stmt = clean_stmt[newline_idx + 1:].strip()
    clean_stmt = clean_stmt.upper()

    if is_mysql:
        err_code = None
        if getattr(exc, "args", None) and len(exc.args) > 0:
            try:
                err_code = int(exc.args[0])
            except (ValueError, TypeError):
                err_code = None

        if err_code is None:
            return False

        # Context 1: ALTER TABLE ... ADD COLUMN -> MySQL 1060 (ER_DUP_FIELDNAME)
        if clean_stmt.startswith("ALTER TABLE") and (" ADD COLUMN " in clean_stmt or " ADD " in clean_stmt):
            return err_code == 1060

        # Context 2: CREATE TABLE -> MySQL 1050 (ER_TABLE_EXISTS_ERROR)
        if bool(re.match(r"^CREATE\s+TABLE\b", clean_stmt)):
            return err_code == 1050

        # Context 3: CREATE INDEX -> MySQL 1061 (ER_DUP_KEYNAME)
        if bool(re.match(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\b", clean_stmt)):
            return err_code == 1061

        return False

    else:
        # SQLite path
        if not isinstance(exc, sqlite3.OperationalError):
            return False

        err_msg = str(exc).lower()

        # Context 1: ALTER TABLE ... ADD COLUMN -> "duplicate column name"
        if clean_stmt.startswith("ALTER TABLE") and (" ADD COLUMN " in clean_stmt or " ADD " in clean_stmt):
            return "duplicate column name" in err_msg

        # Context 2 & 3: CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
        # SQLite natively supports IF NOT EXISTS; any exception raised here is an unexpected failure.
        return False


def init_db():
    db = _get_db()
    schema = _SCHEMA_MYSQL if _USE_MYSQL else _SCHEMA_SQLITE
    db.executescript(schema)
    db.commit()

    # SQLite-only column migrations (MySQL schema is always up-to-date)
    if not _USE_MYSQL:
        for migration in [
            "ALTER TABLE users ADD COLUMN totp_secret TEXT",
            "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN last_login TEXT",
            "ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN locked_until TEXT",
            "ALTER TABLE users ADD COLUMN locked_target TEXT",
            "ALTER TABLE users ADD COLUMN created_by TEXT",
            "ALTER TABLE users ADD COLUMN email TEXT",
            "ALTER TABLE users ADD COLUMN api_token TEXT",
            "ALTER TABLE users ADD COLUMN api_token_created TEXT",
        ]:
            try:
                db.execute(migration)
                db.commit()
            except sqlite3.OperationalError as exc:
                if _is_expected_migration_duplicate(exc, migration, is_mysql=False):
                    pass  # column already exists
                else:
                    logger.error("Legacy column migration failed: %s | %s", migration, exc)
                    raise

    # Incremental migrations (safe to run repeatedly — each is idempotent)
    for migration in [
        "ALTER TABLE users ADD COLUMN api_token TEXT",
        "ALTER TABLE users ADD COLUMN api_token_created TEXT",
        "ALTER TABLE users ADD COLUMN allowed_scanners TEXT DEFAULT NULL",
        # Public shareable report links (SEC-04)
        "ALTER TABLE scan_reports ADD COLUMN share_token TEXT",
        "ALTER TABLE scan_reports ADD COLUMN share_expires_at TEXT",
        # Bug bounty audit trail columns (P0.3)
        "ALTER TABLE scan_reports ADD COLUMN bounty_platform TEXT",
        "ALTER TABLE scan_reports ADD COLUMN bounty_program_handle TEXT",
        "ALTER TABLE scan_reports ADD COLUMN bounty_asset TEXT",
        # Bug bounty findings triage columns (P2.2)
        "ALTER TABLE scan_vulnerabilities ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'New'",
        "ALTER TABLE scan_vulnerabilities ADD COLUMN triage_notes TEXT",
        # AI Opt-Out & Quota tracking (F-03)
        "ALTER TABLE users ADD COLUMN ai_data_sharing_opt_out INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN ai_messages_used INTEGER NOT NULL DEFAULT 0",
        # PhD Opportunity & Discovery Semantics (Gate 1.4.2)
        "ALTER TABLE phd_opportunities ADD COLUMN record_type TEXT DEFAULT 'tracked_opportunity'",
        "ALTER TABLE phd_opportunities ADD COLUMN verification_status TEXT DEFAULT 'unconfirmed'",
        "ALTER TABLE phd_discovery_cache ADD COLUMN record_type TEXT DEFAULT 'verified_vacancy'",
        "ALTER TABLE phd_discovery_cache ADD COLUMN verification_status TEXT DEFAULT 'unconfirmed'",
        # Gate 1.6: Supervisor Briefing Packs & Proof of Work Registry
        """CREATE TABLE IF NOT EXISTS supervisor_briefings (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, opportunity_id TEXT,
            title TEXT NOT NULL, target_supervisor TEXT, share_token TEXT UNIQUE,
            is_shared INTEGER NOT NULL DEFAULT 0, is_revoked INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT, allowed_evidence_ids TEXT, allowed_document_ids TEXT,
            custom_statement TEXT, briefing_payload TEXT, access_count INTEGER NOT NULL DEFAULT 0,
            last_accessed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""",
        """CREATE TABLE IF NOT EXISTS proof_of_work_artifacts (
            id TEXT PRIMARY KEY, user_id INTEGER, category TEXT NOT NULL,
            title TEXT NOT NULL, description TEXT NOT NULL, originating_module TEXT NOT NULL,
            repo_path TEXT, commit_hash TEXT, reproducible_cmd TEXT, actual_result TEXT,
            limitations TEXT, integrity_hash TEXT, verification_method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'VERIFIED', verified_at TEXT,
            is_public_eligible INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""",
        # Gate 1.7: PhD Discovery Source Transparency & Health Registry
        "ALTER TABLE phd_source_health ADD COLUMN source_url TEXT",
        "ALTER TABLE phd_source_health ADD COLUMN source_type TEXT DEFAULT 'official_vacancy_portal'",
        "ALTER TABLE phd_source_health ADD COLUMN access_method TEXT DEFAULT 'API'",
        "ALTER TABLE phd_source_health ADD COLUMN last_http_status INTEGER",
        "ALTER TABLE phd_source_health ADD COLUMN raw_count INTEGER DEFAULT 0",
        "ALTER TABLE phd_source_health ADD COLUMN accepted_count INTEGER DEFAULT 0",
        "ALTER TABLE phd_source_health ADD COLUMN rejected_count INTEGER DEFAULT 0",
        "ALTER TABLE phd_source_health ADD COLUMN last_error_category TEXT",
        "ALTER TABLE phd_source_health ADD COLUMN next_action TEXT",
        "ALTER TABLE phd_source_health ADD COLUMN enabled INTEGER DEFAULT 1",
        """CREATE TABLE IF NOT EXISTS phd_dedup_audit (
            id TEXT PRIMARY KEY, run_timestamp TEXT NOT NULL, raw_count INTEGER NOT NULL,
            unique_count INTEGER NOT NULL, exact_duplicates_merged INTEGER NOT NULL,
            fuzzy_duplicates_flagged INTEGER NOT NULL, backup_file TEXT, audit_summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
        """CREATE TABLE IF NOT EXISTS payments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_ref  TEXT    NOT NULL UNIQUE,
            user_id      INTEGER NOT NULL,
            plan         TEXT    NOT NULL,
            amount       REAL    NOT NULL,
            currency     TEXT    NOT NULL DEFAULT 'DZD',
            created_at   TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ref ON payments (payment_ref)",
        "CREATE INDEX IF NOT EXISTS idx_payments_user ON payments (user_id)",
        # Evaluation Lab Target Registry (Master Spec v5 Phase 1)
        """CREATE TABLE IF NOT EXISTS lab_targets (
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
        )""",
        # Evaluation Lab Ground Truth Registry (Master Spec v5 Phase 2)
        """CREATE TABLE IF NOT EXISTS lab_ground_truth (
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
        )""",
        # Evaluation Lab Benchmarks & Scorecards (Master Spec v5 Phase 2)
        """CREATE TABLE IF NOT EXISTS lab_benchmarks (
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
        )""",
    ]:
        try:
            db.execute(migration)
            db.commit()
        except Exception as exc:
            is_mysql = getattr(db, "_c", None) is not None or _USE_MYSQL
            if _is_expected_migration_duplicate(exc, migration, is_mysql):
                logger.debug("Migration statement skipped (expected duplicate): %s", migration[:60].strip())
            else:
                logger.error("Migration statement failed: %s | error: %s", migration[:80].strip(), exc)
                raise

    # Evaluation Lab Indexes (via strict allowlist and engine-safe helper)
    for (tbl, idx) in LAB_INDEX_ALLOWLIST:
        create_lab_index_if_not_exists(tbl, idx, db=db)

    try:
        # M12: Fix corrupt role data on legacy probe row
        db.execute("UPDATE users SET role = 'analyst' WHERE id = 26 AND length(role) > 20")
        db.commit()
    except Exception as exc:
        logger.error("Legacy probe role update failed: %s", exc)
        raise

    _bootstrap_admin()
    logger.info("database ready | path=%s", DB_PATH)


def _bootstrap_admin():
    """Ensure the default admin and analyst accounts always exist.

    Runs on every startup — safe to call repeatedly.  Skips any account
    that already exists so existing users / passwords are never overwritten.
    This means the accounts always survive a Render restart (fresh ephemeral DB)
    and won't clobber manually-added users.
    """
    import os

    is_prod = (
        os.environ.get("FLASK_ENV") == "production"
        or os.environ.get("PRODUCTION") == "1"
        or os.environ.get("HF_SPACE") == "1"
        or os.environ.get("SPACE_ID") is not None
    )
    if is_prod:
        if not os.environ.get("SECURAX_ADMIN_PASSWORD"):
            raise RuntimeError("SECURAX_ADMIN_PASSWORD must be set in production!")
        if not os.environ.get("SECURAX_ANALYST_PASSWORD"):
            raise RuntimeError("SECURAX_ANALYST_PASSWORD must be set in production!")

    is_testing = bool(
        os.environ.get("TESTING")
        or os.environ.get("FLASK_ENV") == "testing"
        or os.environ.get("PYTEST_CURRENT_TEST")
    )

    admin_env = os.environ.get("SECURAX_ADMIN_PASSWORD", "").strip()
    if admin_env:
        admin_pw = admin_env
        admin_must_change = 0
    elif is_testing:
        admin_pw = "Admin@2024!"
        admin_must_change = 0
    else:
        admin_pw = secrets.token_urlsafe(16)
        admin_must_change = 1
        logger.warning("ADMIN BOOTSTRAP PASSWORD (shown once): %s", admin_pw)

    analyst_env = os.environ.get("SECURAX_ANALYST_PASSWORD", "").strip()
    if analyst_env:
        analyst_pw = analyst_env
        analyst_must_change = 0
    elif is_testing:
        analyst_pw = "Analyst@2024!"
        analyst_must_change = 0
    else:
        analyst_pw = secrets.token_urlsafe(16)
        analyst_must_change = 1
        logger.warning("ANALYST BOOTSTRAP PASSWORD (shown once): %s", analyst_pw)

    now     = datetime.now(timezone.utc).isoformat()
    created = []
    for username, password, role, must_change in [
        ("admin",   admin_pw,   "admin",   admin_must_change),
        ("analyst", analyst_pw, "analyst", analyst_must_change),
    ]:
        # If account already exists, re-hash from environment if password explicitly provided
        exists = _get_db().execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        if exists:
            env_pw = admin_env if username == "admin" else analyst_env
            if env_pw:
                pw_hash = bcrypt.hashpw(env_pw.encode(), bcrypt.gensalt()).decode()
                _get_db().execute(
                    "UPDATE users SET password_hash=?, must_change_password=0, is_active=1 WHERE username=?",
                    (pw_hash, username),
                )
                _get_db().commit()
            continue

        perms = (
            json.dumps(["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"])
            if role == "admin"
            else json.dumps(["run_scan", "view_reports"])
        )
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            _get_db().execute(
                "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by,must_change_password)"
                " VALUES (?,?,?,?,1,?,?,?)",
                (username, pw_hash, role, perms, now, "bootstrap", must_change),
            )
            created.append(username)
        except sqlite3.IntegrityError:
            pass  # race condition on SQLite — another worker beat us to it
        except Exception as exc:
            # Catch specific PyMySQL ER_DUP_ENTRY (1062) for concurrent MySQL worker bootstrap
            err_code = None
            if getattr(exc, "args", None) and len(exc.args) > 0:
                try:
                    err_code = int(exc.args[0])
                except (ValueError, TypeError):
                    err_code = None
            if err_code == 1062:
                pass  # race condition on MySQL — another worker beat us to it
            else:
                logger.error("Admin bootstrap failed for user %s: %s", username, exc)
                raise

    if created:
        _get_db().commit()
        logger.warning(
            "bootstrapped missing accounts: %s — change default passwords immediately!",
            ", ".join(created),
        )



# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(row) -> dict | None:
    if not row:
        return None
    d = dict(row)
    if "permissions" in d and isinstance(d.get("permissions"), str):
        try:
            d["permissions"] = json.loads(d["permissions"])
        except (ValueError, TypeError):
            d["permissions"] = []
    elif not isinstance(d.get("permissions"), list):
        d["permissions"] = []
    # Parse allowed_scanners JSON string → list (None stays None = unrestricted)
    if "allowed_scanners" in d and isinstance(d.get("allowed_scanners"), str):
        try:
            d["allowed_scanners"] = json.loads(d["allowed_scanners"])
        except (ValueError, TypeError):
            d["allowed_scanners"] = None
    return d


def _count_severities(vulns: list) -> tuple[int, int, int, int]:
    c = h = m = l = 0
    for v in vulns:
        s = (v.get("severity") or "info").lower()
        if s == "critical":
            c += 1
        elif s == "high":
            h += 1
        elif s == "medium":
            m += 1
        elif s == "low":
            l += 1
    return c, h, m, l


# ── User functions ────────────────────────────────────────────────────────────

