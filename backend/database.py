import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

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
    if not getattr(_local, "conn", None):
        db_path = _resolve_db_path(_os.environ.get("DB_PATH", "securax.db"))
        conn = sqlite3.connect(db_path, check_same_thread=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return _local.conn


def _resolve_db_path(requested: str) -> str:
    parent = _os.path.dirname(_os.path.abspath(requested))
    if parent:
        try:
            _os.makedirs(parent, exist_ok=True)
            return requested
        except OSError:
            pass
    fallback = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "securax.db")
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
        api_token_created TEXT
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
        # Scanner permission system: NULL = unrestricted (admin/legacy), JSON array = whitelist
        "ALTER TABLE users ADD COLUMN allowed_scanners TEXT DEFAULT NULL",
    ]:
        try:
            db.execute(migration)
            db.commit()
        except sqlite3.OperationalError:
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

def get_user_by_username(username: str) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
    ).fetchone()
    return _norm(row)


def get_user_by_id(user_id: int) -> dict | None:
    row = _get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _norm(row)


def get_all_users(page: int = 1, per_page: int = 100) -> list[dict]:
    offset = (page - 1) * per_page
    return [
        _norm(r) for r in _get_db().execute(
            "SELECT * FROM users ORDER BY id LIMIT ? OFFSET ?", (per_page, offset)
        ).fetchall()
    ]


def count_users() -> int:
    return _get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(username: str, password: str, role: str = "analyst",
                permissions=None, created_by: str | None = None,
                allowed_target: str | None = None,
                email: str | None = None) -> tuple[bool, str]:
    if permissions is None:
        permissions = (
            ["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"]
            if role == "admin"
            else ["run_scan", "view_reports"]
        )
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()
    # allowed_target → stored in locked_target column
    target_val = allowed_target.strip().lower() if allowed_target and allowed_target.strip() else None
    email_val  = email.strip().lower() if email and email.strip() else None
    try:
        _exec(
            "INSERT INTO users (username,email,password_hash,role,permissions,is_active,created_at,created_by,locked_target)"
            " VALUES (?,?,?,?,?,1,?,?,?)",
            (username, email_val, pw_hash, role, json.dumps(permissions), now, created_by, target_val),
        )
        return True, "User created successfully."
    except Exception as exc:
        msg = str(exc).lower()
        if "unique" in msg or "duplicate" in msg or "1062" in msg:
            return False, "Username already exists."
        logger.error("create_user: %s", exc)
        return False, f"Database error: {exc}"


def get_allowed_scanners(user_id: int) -> list[str] | None:
    """Return the whitelist of allowed scanner slugs, or None if unrestricted."""
    row = _get_db().execute(
        "SELECT allowed_scanners FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row:
        return None
    raw = row[0] if isinstance(row, (list, tuple)) else row.get("allowed_scanners")
    if raw is None:
        return None  # unrestricted
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else None
    except Exception:
        return None


def update_user(uid: int, role=None, permissions=None, is_active=None,
                new_password=None, failed_attempts=None, locked_until=None,
                reset_locked_target=False, locked_target_value=_UNSET,
                allowed_scanners=_UNSET, **_) -> tuple[bool, str]:
    fields, values = [], []
    if role            is not None: fields.append("role=?");             values.append(role)
    if permissions     is not None: fields.append("permissions=?");      values.append(json.dumps(permissions))
    if is_active       is not None: fields.append("is_active=?");        values.append(int(is_active))
    if new_password    is not None:
        ph = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        fields.append("password_hash=?"); values.append(ph)
    if failed_attempts is not None: fields.append("failed_attempts=?");  values.append(failed_attempts)
    if locked_until    is not None: fields.append("locked_until=?");     values.append(locked_until)
    if reset_locked_target:
        fields.append("locked_target=?"); values.append(None)
    elif locked_target_value is not _UNSET:
        fields.append("locked_target=?"); values.append(locked_target_value)
    if allowed_scanners is not _UNSET:
        # None → unrestricted (NULL in DB), list → JSON whitelist
        fields.append("allowed_scanners=?")
        values.append(None if allowed_scanners is None else json.dumps(list(allowed_scanners)))
    if not fields:
        return True, ""
    values.append(uid)
    _exec(f"UPDATE users SET {', '.join(fields)} WHERE id=?", tuple(values))
    return True, "Updated successfully."


def update_last_login(user_id: int):
    _exec(
        "UPDATE users SET last_login=?, login_count=login_count+1 WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id),
    )


def get_locked_target(user_id: int) -> str | None:
    """Return the target (hostname/IP) that this analyst is locked to, or None if unset."""
    row = _get_db().execute(
        "SELECT locked_target FROM users WHERE id=?", (user_id,)
    ).fetchone()
    return row["locked_target"] if row else None


def set_locked_target(user_id: int, target: str) -> None:
    """Lock an analyst account to a specific target on their first scan."""
    _exec("UPDATE users SET locked_target=? WHERE id=?", (target, user_id))


def update_user_totp(user_id: int, secret: str, enabled: bool) -> tuple[bool, str]:
    _exec("UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?",
          (secret, int(enabled), user_id))
    return True, ""


def set_api_token(user_id: int, token: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    try:
        _exec("UPDATE users SET api_token=?, api_token_created=? WHERE id=?",
              (token, now, user_id))
    except Exception:
        pass  # api_token column may not exist on very old DBs


def revoke_api_token(user_id: int) -> None:
    try:
        _exec("UPDATE users SET api_token=NULL, api_token_created=NULL WHERE id=?", (user_id,))
    except Exception:
        pass


def get_user_by_api_token(token: str) -> dict | None:
    try:
        row = _get_db().execute(
            "SELECT * FROM users WHERE api_token=? AND is_active=1", (token,)
        ).fetchone()
        return _norm(row)
    except Exception:
        return None


def delete_user(uid: int) -> tuple[bool, str]:
    """Soft delete — deactivates the user without removing the record."""
    _exec("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    return True, "User deactivated."


def hard_delete_user(uid: int) -> tuple[bool, str]:
    _exec("DELETE FROM users WHERE id=?", (uid,))
    return True, "User deleted."


def count_active_admins() -> int:
    return _get_db().execute(
        "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
    ).fetchone()[0]


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_event(action: str, username: str = "", user_id: int | None = None,
              category: str = "general", resource: str = "", ip_address: str = "",
              user_agent: str = "", status: str = "success", details: str = "", **_):
    try:
        _exec(
            "INSERT INTO audit_logs"
            " (action,username,user_id,category,resource,ip_address,user_agent,status,details,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (action, username, user_id, category, resource, ip_address,
             user_agent, status, details, datetime.now(timezone.utc).isoformat()),
        )
    except Exception as exc:
        logger.warning("log_event failed: %s", exc)


def get_audit_log(user_id: int | None = None, category: str | None = None,
                  action: str | None = None, limit: int = 200,
                  date_from: str | None = None, date_to: str | None = None,
                  page: int = 1, per_page: int | None = None) -> tuple[list[dict], int]:
    clauses, params = [], []
    if user_id   is not None: clauses.append("user_id=?");         params.append(user_id)
    if category:              clauses.append("category=?");         params.append(category)
    if action:                clauses.append("action LIKE ?");      params.append(f"%{action}%")
    if date_from:             clauses.append("created_at >= ?");    params.append(date_from)
    if date_to:               clauses.append("created_at <= ?");    params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    db    = _get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    if per_page:
        offset = (max(page, 1) - 1) * per_page
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
    else:
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows], total


def get_audit_stats() -> dict:
    db = _get_db()
    total  = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    failed = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE status='failed'"
    ).fetchone()[0]
    by_cat = db.execute(
        "SELECT category, COUNT(*) as c FROM audit_logs GROUP BY category ORDER BY c DESC"
    ).fetchall()
    recent = db.execute(
        "SELECT username, action, created_at FROM audit_logs "
        "WHERE category='auth' ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_events":  total,
        "failed_events": failed,
        "by_category":   [{"category": r["category"], "count": r["c"]} for r in by_cat],
        "recent_logins": [dict(r) for r in recent],
    }


# ── Report functions ──────────────────────────────────────────────────────────

def store_report(result: dict, risk_score: float, original_content: str | None,
                 user_id: int, username: str) -> str:
    token = uuid.uuid4().hex
    vulns = result.get("vulnerabilities", [])
    c, h, m, l = _count_severities(vulns)
    now = datetime.now(timezone.utc).isoformat()
    db = _get_db()
    try:
        cursor = db.execute(
            "INSERT INTO scan_reports"
            " (token,user_id,username,scan_type,target,risk_score,vuln_count,"
            "  critical_count,high_count,medium_count,low_count,result_json,original_content,stored_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (token, user_id, username,
             result.get("scan_type", ""), result.get("target", ""),
             risk_score, len(vulns), c, h, m, l,
             json.dumps(result), original_content, now),
        )
        report_id = cursor.lastrowid

        for vuln in vulns:
            sev = (str(vuln.get("severity", "low")).strip().lower() or "low")
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "low"
            raw_cves = vuln.get("cve_ids", [])
            if isinstance(raw_cves, str):
                cve_list = [c.strip() for c in raw_cves.split(",") if c.strip()]
            elif isinstance(raw_cves, list):
                cve_list = [str(c).strip() for c in raw_cves if str(c).strip()]
            else:
                cve_list = []
            db.execute(
                "INSERT INTO scan_vulnerabilities"
                " (report_id,check_name,severity,title,description,evidence,"
                "  remediation,line_number,cve_ids,is_fixed,fixed_at,found_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,0,NULL,?)",
                (
                    report_id,
                    str(vuln.get("check", "unknown_check")),
                    sev,
                    str(vuln.get("title", "Untitled finding")),
                    str(vuln.get("description", "")),
                    str(vuln.get("evidence", "")),
                    str(vuln.get("remediation", "")),
                    int(vuln.get("line_number", 0) or 0),
                    json.dumps(cve_list),
                    now,
                ),
            )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return token


def get_report(token: str) -> dict | None:
    row = _get_db().execute("SELECT * FROM scan_reports WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d["result_json"])
    return d


def get_user_reports(user_id: int, limit: int = 100) -> list[dict]:
    return [dict(r) for r in _get_db().execute(
        "SELECT token,user_id,username,scan_type,target,risk_score,vuln_count,"
        "critical_count,high_count,medium_count,low_count,stored_at"
        " FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()]


def get_all_reports(limit: int = 200, date_from: str | None = None,
                    date_to: str | None = None, scan_type: str | None = None,
                    username: str | None = None) -> list[dict]:
    clauses, params = [], []
    if date_from: clauses.append("stored_at >= ?");  params.append(date_from)
    if date_to:   clauses.append("stored_at <= ?");  params.append(date_to)
    if scan_type: clauses.append("scan_type=?");     params.append(scan_type)
    if username:  clauses.append("username LIKE ?"); params.append(f"%{username}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return [dict(r) for r in _get_db().execute(
        f"SELECT * FROM scan_reports {where} ORDER BY stored_at DESC LIMIT ?", params
    ).fetchall()]


def delete_report(token: str) -> tuple[bool, str]:
    _exec("DELETE FROM scan_reports WHERE token=?", (token,))
    return True, "Report deleted."


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats(user_id: int) -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports WHERE user_id=? GROUP BY scan_type",
        (user_id,),
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT 10",
        (user_id,),
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_all_dashboard_stats() -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports").fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports").fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports GROUP BY scan_type"
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_system_stats() -> dict:
    db   = _get_db()
    now  = datetime.now(timezone.utc)
    today = now.date().isoformat()

    # ── Basic counts ──────────────────────────────────────────────────────────
    total_users  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    total_scans  = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    total_vulns  = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical     = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    today_scans  = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at LIKE ?", (f"{today}%",)
    ).fetchone()[0]

    # ── This week ─────────────────────────────────────────────────────────────
    week_scans = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at >= date('now','-7 days')"
    ).fetchone()[0]

    # ── Failed logins today ───────────────────────────────────────────────────
    failed_logins = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE action='login_failed' AND created_at LIKE ?",
        (f"{today}%",),
    ).fetchone()[0]

    # ── Risk distribution ─────────────────────────────────────────────────────
    risk_row = db.execute(
        "SELECT "
        "  SUM(CASE WHEN risk_score >= 9.0 THEN 1 ELSE 0 END) as critical,"
        "  SUM(CASE WHEN risk_score >= 7.0 AND risk_score < 9.0 THEN 1 ELSE 0 END) as high,"
        "  SUM(CASE WHEN risk_score >= 4.0 AND risk_score < 7.0 THEN 1 ELSE 0 END) as medium,"
        "  SUM(CASE WHEN risk_score >= 1.0 AND risk_score < 4.0 THEN 1 ELSE 0 END) as low,"
        "  SUM(CASE WHEN risk_score < 1.0 THEN 1 ELSE 0 END) as minimal "
        "FROM scan_reports"
    ).fetchone()
    risk_distribution = {
        "critical": int(risk_row["critical"] or 0),
        "high":     int(risk_row["high"]     or 0),
        "medium":   int(risk_row["medium"]   or 0),
        "low":      int(risk_row["low"]      or 0),
        "minimal":  int(risk_row["minimal"]  or 0),
    }

    # ── Top scan types ────────────────────────────────────────────────────────
    top_scan_types = [
        {"type": r["scan_type"], "count": r["c"]}
        for r in db.execute(
            "SELECT scan_type, COUNT(*) as c FROM scan_reports "
            "GROUP BY scan_type ORDER BY c DESC"
        ).fetchall()
    ]

    # ── Recent scans (last 10) ────────────────────────────────────────────────
    recent_scans = [
        dict(r) for r in db.execute(
            "SELECT token,username,scan_type,target,risk_score,vuln_count,stored_at "
            "FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
        ).fetchall()
    ]

    # ── Top scanners ──────────────────────────────────────────────────────────
    top_scanners = db.execute(
        "SELECT username, COUNT(*) as c FROM scan_reports "
        "GROUP BY username ORDER BY c DESC LIMIT 5"
    ).fetchall()

    # ── Recent events ─────────────────────────────────────────────────────────
    recent_events = db.execute(
        "SELECT action, username, created_at FROM audit_logs "
        "ORDER BY created_at DESC LIMIT 10"
    ).fetchall()

    # ── Users list (for admin user management) ────────────────────────────────
    users_list = [_norm(r) for r in db.execute("SELECT * FROM users ORDER BY id").fetchall()]

    return {
        "total_users":       total_users,
        "active_users":      active_users,
        "total_scans":       total_scans,
        "today_scans":       today_scans,
        "scans_this_week":   week_scans,
        "total_vulns":       int(total_vulns),
        "critical_vulns":    int(critical),
        "failed_logins":     failed_logins,
        "risk_distribution": risk_distribution,
        "top_scan_types":    top_scan_types,
        "recent_scans":      recent_scans,
        "recent_events":     [dict(r) for r in recent_events],
        "top_scanners":      [{"username": r["username"], "count": r["c"]} for r in top_scanners],
        "users_list":        users_list,
    }


def get_top_vulnerabilities(limit: int = 10) -> list[dict]:
    """Return the most frequent vulnerability check_names from the dedicated table."""
    rows = _get_db().execute(
        "SELECT check_name, severity, COUNT(*) AS count"
        " FROM scan_vulnerabilities"
        " GROUP BY check_name, severity"
        " ORDER BY count DESC"
        " LIMIT ?",
        (limit,),
    ).fetchall()
    if rows:
        return [{"title": r["check_name"], "severity": r["severity"], "count": r["count"]}
                for r in rows]
    # Fallback: parse result_json for databases that predate the scan_vulnerabilities table
    result_rows = _get_db().execute(
        "SELECT result_json FROM scan_reports ORDER BY stored_at DESC LIMIT 100"
    ).fetchall()
    counts: dict[str, dict] = {}
    for row in result_rows:
        try:
            vulns = json.loads(row["result_json"]).get("vulnerabilities", [])
        except (ValueError, TypeError):
            continue
        for v in vulns:
            title = (v.get("title") or v.get("check") or "Unknown")[:80]
            sev   = (v.get("severity") or "info").lower()
            if title not in counts:
                counts[title] = {"title": title, "severity": sev, "count": 0}
            counts[title]["count"] += 1
    ordered = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
    return ordered[:limit]


# ── Scan Jobs (persistent background jobs) ────────────────────────────────────

def upsert_job(job: dict) -> None:
    """Insert or replace a background scan job record."""
    _exec(
        "INSERT OR REPLACE INTO scan_jobs"
        " (job_id,scan_type,target,user_id,username,status,progress,message,"
        "  result_json,error,report_token,started_at,completed_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            job["job_id"], job["scan_type"], job["target"],
            job["user_id"], job["username"], job["status"],
            job["progress"], job["message"],
            json.dumps(job.get("result")) if job.get("result") is not None else None,
            job.get("error"), job.get("report_token"),
            job["started_at"], job.get("completed_at"),
        ),
    )


def get_job_from_db(job_id: str) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("result_json"):
        try:
            d["result"] = json.loads(d["result_json"])
        except (ValueError, TypeError):
            d["result"] = None
    else:
        d["result"] = None
    return d


def get_user_jobs_from_db(user_id: int, limit: int = 20) -> list[dict]:
    rows = _get_db().execute(
        "SELECT job_id,scan_type,target,user_id,username,status,progress,"
        "message,error,report_token,started_at,completed_at"
        " FROM scan_jobs WHERE user_id=? ORDER BY started_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def purge_old_jobs(ttl_minutes: int = 60) -> int:
    """Delete completed/errored jobs older than ttl_minutes. Returns count deleted."""
    cutoff = (datetime.now(timezone.utc) - __import__("datetime").timedelta(minutes=ttl_minutes)).isoformat()
    cur = _exec(
        "DELETE FROM scan_jobs WHERE status IN ('done','error') AND completed_at < ?",
        (cutoff,),
    )
    return cur.rowcount if hasattr(cur, "rowcount") else 0


# ── Scheduled Scans ───────────────────────────────────────────────────────────

def create_scheduled_scan(user_id: int, username: str, scan_type: str,
                          target: str, cron_expr: str = "daily") -> int:
    from datetime import timedelta
    next_run = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    cur = _exec(
        "INSERT INTO scheduled_scans"
        " (user_id,username,scan_type,target,cron_expr,is_active,next_run_at,created_at)"
        " VALUES (?,?,?,?,?,1,?,?)",
        (user_id, username, scan_type, target, cron_expr, next_run,
         datetime.now(timezone.utc).isoformat()),
    )
    return cur.lastrowid


def get_user_scheduled_scans(user_id: int) -> list[dict]:
    rows = _get_db().execute(
        "SELECT * FROM scheduled_scans WHERE user_id=? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_scheduled_scans() -> list[dict]:
    rows = _get_db().execute(
        "SELECT * FROM scheduled_scans WHERE is_active=1 ORDER BY next_run_at ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def update_scheduled_scan_run(sched_id: int, last_run_at: str, next_run_at: str) -> None:
    _exec(
        "UPDATE scheduled_scans SET last_run_at=?, next_run_at=? WHERE id=?",
        (last_run_at, next_run_at, sched_id),
    )


def toggle_scheduled_scan(sched_id: int, user_id: int, active: bool) -> bool:
    cur = _exec(
        "UPDATE scheduled_scans SET is_active=? WHERE id=? AND user_id=?",
        (int(active), sched_id, user_id),
    )
    return (cur.rowcount if hasattr(cur, "rowcount") else 1) > 0


def delete_scheduled_scan(sched_id: int, user_id: int) -> bool:
    cur = _exec(
        "DELETE FROM scheduled_scans WHERE id=? AND user_id=?",
        (sched_id, user_id),
    )
    return (cur.rowcount if hasattr(cur, "rowcount") else 1) > 0
