# SecuraX — System Architecture

> **Version**: 2.0.0 | **Last updated**: 2026-07-30

## Table of Contents

1. [Overview](#overview)
2. [Component Diagram](#component-diagram)
3. [Request / Data Flow](#request--data-flow)
4. [Backend Components](#backend-components)
5. [Scanner Pipeline](#scanner-pipeline)
6. [Risk Scoring Pipeline](#risk-scoring-pipeline)
7. [Database Schema](#database-schema)
8. [Security Architecture](#security-architecture)
9. [Design Decisions](#design-decisions)
10. [Known Limitations](#known-limitations)

---

## Overview

SecuraX is structured as a **decoupled two-tier web application**:

| Tier | Technology | Deployment |
|------|-----------|-----------|
| **Frontend SPA** | React 19 + Vite 8 + Tailwind CSS 3 | Vercel / Netlify |
| **Backend REST API** | Flask 3.1 + Gunicorn + Python 3.11+ | Render / PythonAnywhere / Docker |
| **Persistence** | SQLite (WAL mode) → PostgreSQL (planned) | Co-located with backend |

Communication is exclusively via a **JSON REST API** over HTTPS. The frontend is
a pure SPA with no server-side rendering. This separation allows the backend to be
used independently as a headless API for research automation.

---

## Component Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                   Frontend (React SPA)                         │
│  React 19 · Vite 8 · Tailwind CSS · Framer Motion             │
│  React Router 7 · Axios · i18n (AR/EN)                        │
└──────────────────────────┬─────────────────────────────────────┘
                           │  HTTPS · JSON REST API
                           │  Cookie-based session auth
┌──────────────────────────▼─────────────────────────────────────┐
│                   Backend (Flask API)                           │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Blueprints  │  │ ARIA Agent  │  │  Scanner Engines      │   │
│  │  auth       │  │ (ai_agent)  │  │  web_scanner.py       │   │
│  │  scans      │  │ Gemini 1.5  │  │  dast_scanner.py      │   │
│  │  admin      │  │ NVD API     │  │  sast_scanner.py      │   │
│  │  reports    │  │ ATT&CK maps │  │  netscan_scanner.py   │   │
│  │  ai_routes  │  └─────────────┘  │  ssl_scanner.py       │   │
│  │  scheduled  │                   │  dep_scanner.py       │   │
│  │  extra_scan │  ┌─────────────┐  │  server_int.py        │   │
│  │  domain_ver │  │ Risk Engine │  │  server_ext.py        │   │
│  └─────────────┘  │(risk_engine)│  │  docker_scanner.py    │   │
│                   └─────────────┘  │  dns_scanner.py       │   │
│  ┌─────────────┐  ┌─────────────┐  │  wordpress_scanner.py │   │
│  │ Job Manager │  │   Middleware│  └──────────────────────┘   │
│  │(job_manager)│  │  (security  │                              │
│  │  SQLite WAL │  │   headers,  │  ┌──────────────────────┐   │
│  └─────────────┘  │   CORS,     │  │  Report Generator    │   │
│                   │   logging)  │  │  (report_generator)  │   │
│  ┌─────────────┐  └─────────────┘  │  PDF · Arabic · EN   │   │
│  │  Extensions │                   └──────────────────────┘   │
│  │ Flask-Login │                                               │
│  │ Flask-WTF   │                                               │
│  │ Flask-Limit │                                               │
│  │ Flask-CORS  │                                               │
│  └─────────────┘                                               │
└──────────────────────────┬─────────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────────┐
│              Database (SQLite WAL / PostgreSQL)                  │
│  users · scan_reports · scan_vulnerabilities                    │
│  audit_logs · scan_jobs · scheduled_scans · migrations          │
└────────────────────────────────────────────────────────────────┘
```

---

## Request / Data Flow

### Synchronous Scan

```
Client → POST /api/scan/web → scans.py blueprint
  → utils.validate_target()
  → web_scanner.run_web_scan(target)
  → risk_engine.calculate_risk_v2(result)
  → database.store_report(result, risk_score)
  → [optional] ai_agent.generate_aria_analysis(result)
  → Response: {report_token, risk_score, summary}
```

### Asynchronous Scan (Background Job)

```
Client → POST /api/scan/async/web → scans.py
  → job_manager.create_job(scan_type, target, user_id)
  → job_manager.run_in_background(job_id, fn)
  → Response: {job_id}  ← immediately (202 Accepted)

Background thread:
  → fn() = web_scanner.run_web_scan(target)
  → job_manager.update_job(status="done", result=...)
  → database.store_report(...)

Client → GET /api/scan/job/<job_id> → poll status
```

---

## Backend Components

### `app.py` — Application Factory
Creates the Flask application using the Application Factory pattern.
Wires extensions (`extensions.py`), middleware (`middleware.py`), blueprints,
and the user loader. Strips HTTP proxy environment variables to prevent
scanner traffic from being intercepted.

**Design decision**: Application Factory (not module-level app creation) is used
so that tests can create isolated app instances with different configurations.

### `extensions.py` — Shared Flask Extensions
All Flask extension objects (CSRFProtect, LoginManager, Limiter, CORS) are
instantiated here and bound to the app via `init_extensions(app)`.

**Design decision**: Blueprints import from `extensions.py`, never from `app.py`,
to prevent circular imports.

### `database.py` — Database Abstraction Layer
Provides a thin SQLite abstraction using thread-local connections and WAL mode.
All SQL is parameterised to prevent injection. Supports migration to PostgreSQL
via environment variable (`MYSQL_*` vars, despite the naming).

**Design decision**: Raw SQL + thread-local connections (not SQLAlchemy ORM) was
chosen for simplicity and to avoid ORM overhead in a scan-intensive workload.

### `models.py` — User Model
Pure Python `User` class implementing `flask_login.UserMixin`. No ORM dependency.
Implements timing-attack-resistant authentication via constant-time bcrypt.

### `risk_engine.py` — Risk Scoring Engine
See [Risk Scoring Pipeline](#risk-scoring-pipeline) and `docs/RISK_ENGINE.md`.

### `job_manager.py` — Background Job Queue
In-memory dict + SQLite persistence. Jobs survive server restarts because state
is written to `scan_jobs` table on every status change.

**Design decision**: In-process threading (not Celery/Redis) was chosen because
the deployment target is single-process Gunicorn on free-tier hosting. A Celery
migration path exists via the `RATELIMIT_STORAGE_URI` config.

### `ai_agent.py` — ARIA Intelligence Agent
Five-stage autonomous agent: (1) NVD CVE enrichment, (2) MITRE ATT&CK mapping,
(3) attack chain generation, (4) remediation planning, (5) compliance assessment.
Calls Google Gemini 1.5 Flash API. Gracefully degrades if API key is absent.

### `report_generator.py` — PDF Report Generator
Generates professional PDF reports using ReportLab with Arabic reshaping
(`arabic-reshaper` + `python-bidi`). Supports both RTL (Arabic) and LTR (English).

### `middleware.py` — Security Middleware
Registers `after_request` hooks for security headers:
CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy.

---

## Scanner Pipeline

Each scanner module follows the same contract (see `backend/scanners/schema.py`):

```python
def run_<type>_scan(target: str, **options) -> dict:
    """
    Returns:
        {
            "scan_type": str,           # one of the 11 scanner types
            "target": str,              # the scanned target
            "vulnerabilities": [        # list of findings
                {
                    "severity": str,    # critical|high|medium|low|info
                    "check": str,       # machine-readable check ID
                    "title": str,       # human-readable title
                    "description": str, # detailed description
                    "evidence": str,    # optional: proof of finding
                    "cve_ids": list,    # optional: CVE identifiers
                    "cwe_id": str,      # optional: CWE identifier
                    "owasp_category": str, # optional: OWASP Top 10 category
                    "remediation": str, # optional: fix guidance
                }
            ],
            "scanner_versions": dict,   # versions of tools invoked
            "scan_duration_s": float,   # wall-clock scan time
            "timestamp": str,           # ISO 8601
        }
    """
```

---

## Risk Scoring Pipeline

See `docs/RISK_ENGINE.md` for the full mathematical specification.

```
Input: scan_result, criticality, exploit_known, internet_facing, has_pii, has_payment
  │
  ▼
Step 1: Per-finding score
  base_score(severity) × type_booster(check_text) × exploit_factor(KEV/known)
  │
  ▼
Step 2: Logarithmic aggregation (decay_factor = 0.85 per finding)
  raw_score = Σ (individual_score × 0.85^i)
  │
  ▼
Step 3: Sigmoid normalisation → [0, 10]
  base_score = 10 × (1 - exp(-raw/15))
  │
  ▼
Step 4: Temporal adjustment
  temporal = base × (1 + 0.05·has_cve + 0.15·kev_hit + 0.10·exploit_known)
  │
  ▼
Step 5: Environmental adjustment
  env = temporal × criticality × 1.20^internet × 1.15^pii × 1.20^payment × scan_weight
  │
  ▼
Step 6: Floor guarantees (critical ≥ 7.5, high ≥ 5.0)
  final = max(env, floor)

Output: RiskBreakdown dataclass
```

---

## Database Schema

```sql
-- Users and authentication
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst',
    permissions     TEXT NOT NULL DEFAULT '[]',  -- JSON array
    totp_secret     TEXT,
    totp_enabled    INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until    TEXT,
    is_active       INTEGER DEFAULT 1,
    last_login      TEXT,
    login_count     INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    allowed_scanners TEXT,  -- JSON array or NULL (unrestricted)
    approved_target TEXT
);

-- Scan reports (one per completed scan)
CREATE TABLE scan_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT UNIQUE NOT NULL,  -- 32-char hex UUID
    user_id     INTEGER NOT NULL,
    username    TEXT NOT NULL,
    scan_type   TEXT NOT NULL,
    target      TEXT NOT NULL,
    risk_score  REAL,
    result_json TEXT NOT NULL,          -- full scan result (JSON)
    aria_json   TEXT,                   -- ARIA analysis (JSON), nullable
    created_at  TEXT NOT NULL
);

-- Individual vulnerabilities (denormalised for fast querying)
CREATE TABLE scan_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL REFERENCES scan_reports(id),
    severity    TEXT NOT NULL,
    check_name  TEXT,
    title       TEXT,
    cve_ids     TEXT  -- JSON array
);

-- Background scan jobs
CREATE TABLE scan_jobs (
    job_id       TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    username     TEXT NOT NULL,
    scan_type    TEXT NOT NULL,
    target       TEXT NOT NULL,
    status       TEXT NOT NULL,  -- queued|running|done|error
    progress     INTEGER DEFAULT 0,
    message      TEXT,
    result_json  TEXT,
    error        TEXT,
    report_token TEXT,
    started_at   TEXT NOT NULL,
    completed_at TEXT
);

-- Scheduled scans
CREATE TABLE scheduled_scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    username    TEXT NOT NULL,
    scan_type   TEXT NOT NULL,
    target      TEXT NOT NULL,
    frequency   TEXT NOT NULL,  -- daily|weekly|monthly
    is_active   INTEGER DEFAULT 1,
    last_run    TEXT,
    next_run    TEXT,
    created_at  TEXT NOT NULL
);

-- Audit log (append-only)
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    username   TEXT,
    user_id    INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    category   TEXT,
    details    TEXT,
    created_at TEXT NOT NULL
);
```

---

## Security Architecture

See `SECURITY.md` for the full security policy and responsible disclosure process.

### Defence-in-depth layers

1. **Transport**: HTTPS enforced in production via HSTS header
2. **Authentication**: bcrypt (12 rounds) + TOTP (RFC 6238) + account lockout
3. **Authorisation**: RBAC with `@require_permission()` decorator
4. **Session**: HttpOnly + SameSite cookies, 30-minute idle timeout
5. **Input**: URL sanitisation, extension blocklist, ZIP bomb guard
6. **CSRF**: Flask-WTF token on all state-changing endpoints
7. **Rate limiting**: Per-user, per-endpoint (Flask-Limiter)
8. **Audit**: Every sensitive action logged with IP + user-agent
9. **Headers**: CSP nonce + HSTS + X-Frame-Options: DENY + Referrer-Policy

---

## Design Decisions

### DD-001: Application Factory Pattern
**Decision**: Use `create_app()` factory function, not module-level app creation.
**Rationale**: Enables isolated test instances; follows Flask best practices.
**Trade-off**: Slightly more verbose setup vs. simpler module-level global.

### DD-002: Raw SQL over SQLAlchemy ORM
**Decision**: Use parameterised raw SQL with thread-local connections.
**Rationale**: No ORM overhead for high-volume scan writes; smaller dependency footprint.
**Trade-off**: Manual migration management vs. Alembic auto-migration.

### DD-003: In-process threading over Celery
**Decision**: Background scan jobs run in daemon threads within the Flask process.
**Rationale**: Free-tier hosting (Render, PythonAnywhere) does not support separate
worker processes. The current workload fits within a single process.
**Trade-off**: No job persistence across process crashes (mitigated by SQLite WAL
persistence of job state). A Celery migration is documented in `RESEARCH_ROADMAP.md`.

### DD-004: No AI by default
**Decision**: ARIA analysis is optional and requires a `GEMINI_API_KEY`.
**Rationale**: Per the SecuraX philosophy, AI must increase scientific value, not
complexity. The risk engine and scanner outputs are complete and useful without AI.
The AI layer adds explanation and compliance mapping but is not required for correctness.

### DD-005: SQLite WAL over PostgreSQL
**Decision**: Default to SQLite with WAL mode; PostgreSQL supported via env vars.
**Rationale**: Zero-dependency deployment for researchers who want to run locally.
WAL mode provides safe concurrent reads during write-heavy scan sessions.
**Trade-off**: Not suitable for high-concurrency multi-tenant deployment.

---

## Known Limitations

- **Single-process threading**: Background jobs share the Flask process. Under heavy
  concurrent load, slow scanners (Nmap, ZAP) may degrade API responsiveness.
- **SQLite concurrency**: Write lock prevents parallel writes. PostgreSQL migration
  required for multi-user production deployments with high scan frequency.
- **No job cancellation**: Running background jobs cannot be interrupted once started.
- **ARIA rate limiting**: Gemini API rate limits may cause ARIA analysis to fail
  on high-volume scan sessions; failures are gracefully handled (degraded to no-AI mode).
- **Scanner binary dependencies**: DAST scanner (ZAP, Nikto, Nuclei) and Network
  scanner (Nmap) require system-level installation. They gracefully skip if not found.
