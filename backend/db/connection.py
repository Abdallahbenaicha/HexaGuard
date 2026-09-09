import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt

logger = logging.getLogger(__name__)

import os as _os

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

class _MySQLAdapter:
    """Thin wrapper that makes a pymysql connection look like sqlite3.Connection."""

    def __init__(self, conn):
        self._c = conn

    def _fix(self, sql: str) -> str:
        return sql.replace("?", "%s")

    def execute(self, sql: str, params=()):
        sql = self._fix(sql)
        cur = self._c.cursor()
        cur.execute(sql, params)
        self._c.commit()
        return cur

    def executescript(self, sql: str):
        cur = self._c.cursor()
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt and not stmt.startswith("--"):
                try:
                    cur.execute(stmt)
                except Exception as exc:
                    logger.debug("executescript stmt skipped: %s | %s", stmt[:60], exc)
        self._c.commit()

    def commit(self):
        self._c.commit()

    def rollback(self):
        self._c.rollback()


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
        conn = sqlite3.connect(db_path, check_same_thread=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
        _local.conn_path = db_path
    return _local.conn


def _resolve_db_path(requested: str) -> str:
    parent = _os.path.dirname(_os.path.abspath(requested))
    if parent:
        try:
            _os.makedirs(parent, exist_ok=True)
            return requested
        except OSError:
            pass
    backend_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    fallback = _os.path.join(backend_dir, "securax.db")
    logger.warning(
        "DB path '%s' is not accessible — falling back to '%s'.",
        requested, fallback,
    )
    return fallback

DB_PATH = _os.environ.get("DB_PATH", "securax.db")


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
        ai_messages_used INTEGER NOT NULL DEFAULT 0
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
        api_token_created VARCHAR(50)
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
"""


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
            except sqlite3.OperationalError:
                pass  # column already exists

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
    ]:
        try:
            db.execute(migration)
            db.commit()
        except (sqlite3.OperationalError, Exception):
            pass  # column already exists

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

    admin_pw   = os.environ.get("SECURAX_ADMIN_PASSWORD",   "").strip() or "Admin@2024!"
    analyst_pw = os.environ.get("SECURAX_ANALYST_PASSWORD", "").strip() or "Analyst@2024!"

    now     = datetime.now(timezone.utc).isoformat()
    created = []
    for username, password, role in [
        ("admin",   admin_pw,   "admin"),
        ("analyst", analyst_pw, "analyst"),
    ]:
        # Skip if account already exists (never overwrite)
        exists = _get_db().execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if exists:
            continue

        perms = (
            json.dumps(["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"])
            if role == "admin"
            else json.dumps(["run_scan", "view_reports"])
        )
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            _get_db().execute(
                "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by)"
                " VALUES (?,?,?,?,1,?,?)",
                (username, pw_hash, role, perms, now, "bootstrap"),
            )
            created.append(username)
        except sqlite3.IntegrityError:
            pass  # race condition — another worker beat us to it

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

