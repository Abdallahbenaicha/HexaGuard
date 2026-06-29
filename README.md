# HexaGuard — Unified Security Scanning Platform

> **All-in-one cybersecurity platform** for SMBs and security teams — web, network, DAST, SSL, server, code & dependency scanning in a single dashboard, with Arabic/English support.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#testing)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![React](https://img.shields.io/badge/react-18-61dafb)](https://react.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Testing](#testing)
- [Security](#security)
- [Roadmap](#roadmap)

---

## Features

| Feature | Description |
|---|---|
| **7 Scan Types** | Web (OWASP), Network (ext/int), DAST, SSL/TLS, Server config, SAST, Dependencies |
| **Background Scans** | Queue scans and navigate freely — browser notifications on completion |
| **Scheduled Scans** | Daily / weekly / monthly recurring scans per user |
| **AI Security Assistant** | ARIA chatbot for real-time security guidance (Arabic + English) |
| **Admin Dashboard** | System-wide stats, user management, 7-day trend charts |
| **PDF Reports** | Professional export with CVSS scores, OWASP mapping, remediation |
| **Audit Logs** | Full event trail for compliance (SOC 2 / ISO 27001) |
| **Role-Based Access** | Admin / Analyst roles with per-user target locking |
| **Arabic + English** | Full RTL/LTR i18n — rare in security tools |
| **Dark / Light Mode** | Persistent theme preference |
| **Command Palette** | Ctrl+K quick navigation across all features |

---

## Architecture

```
┌────────────────────────────────────────────────┐
│              Frontend (Vercel)                  │
│        React 18 + Vite + Tailwind CSS           │
│  Framer Motion · Lucide Icons · Axios · i18n    │
└────────────────────┬───────────────────────────┘
                     │ HTTPS REST API
┌────────────────────▼───────────────────────────┐
│           Backend (PythonAnywhere)              │
│       Flask 3 · uWSGI · Python 3.13             │
│  auth · scans · reports · admin ·               │
│  ai_routes · scheduled blueprints               │
│  Flask-WTF CSRF · Flask-Limiter · bcrypt        │
└────────────────────┬───────────────────────────┘
                     │
┌────────────────────▼───────────────────────────┐
│              Database (SQLite WAL)              │
│  users · scan_reports · scan_vulnerabilities    │
│  audit_logs · scan_jobs · scheduled_scans       │
└────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+

### 1 — Backend

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit SECRET_KEY
python app.py
# → http://localhost:5000
```

### 2 — Frontend

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:5000" > .env.local
npm run dev
# → http://localhost:5173
```

### Default Credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@2024!` |
| Analyst | `analyst` | `Analyst@2024!` |

> **Change these immediately after first login.**

---

## Environment Variables

### Backend (`.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ✅ | — | Flask session secret (min 32 chars random) |
| `FLASK_ENV` | — | `development` | Set `production` on server |
| `DB_PATH` | — | `hexaguard.db` | SQLite file path |
| `MYSQL_HOST` | — | — | Enable MySQL (set all 4 MYSQL_* vars) |
| `MYSQL_USER` | — | — | MySQL username |
| `MYSQL_PASS` | — | — | MySQL password |
| `MYSQL_DB` | — | `hexaguard` | MySQL database name |
| `HEXAGUARD_ADMIN_PASSWORD` | — | `Admin@2024!` | Bootstrap admin password |
| `ALLOWED_ORIGINS` | — | `http://localhost:5173` | Comma-separated CORS origins |

### Frontend (`.env.local`)

| Variable | Required | Description |
|---|---|---|
| `VITE_API_BASE_URL` | ✅ | Backend URL (no trailing slash) |

---

## API Reference

### Authentication

| Method | Endpoint | Body / Params |
|---|---|---|
| `POST` | `/api/login` | `{username, password}` |
| `POST` | `/api/logout` | — |
| `GET` | `/api/profile` | — |

### Scans (synchronous)

| Method | Endpoint | Body |
|---|---|---|
| `POST` | `/api/scan/web` | `{url, mode}` |
| `POST` | `/api/scan/network` | `{target, mode}` |
| `POST` | `/api/scan/dast` | `{url}` |
| `POST` | `/api/scan/ssl` | `{host}` |
| `POST` | `/api/scan/server` | `{target, mode}` |

### Scans (background / async)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/async/web` | Queue web scan |
| `POST` | `/api/scan/async/network` | Queue network scan |
| `POST` | `/api/scan/async/dast` | Queue DAST scan |
| `POST` | `/api/scan/async/ssl` | Queue SSL scan |
| `POST` | `/api/scan/async/server` | Queue server scan |
| `GET` | `/api/scan/job/<id>` | Poll job status |
| `GET` | `/api/scan/jobs` | List active jobs |

### Scheduled Scans

| Method | Endpoint | Body |
|---|---|---|
| `GET` | `/api/scheduled-scans` | — |
| `POST` | `/api/scheduled-scans` | `{scan_type, target, cron_expr}` |
| `PATCH` | `/api/scheduled-scans/<id>` | `{is_active: bool}` |
| `DELETE` | `/api/scheduled-scans/<id>` | — |

`cron_expr` values: `daily` · `weekly` · `monthly`

### Reports

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/reports` | User report list |
| `GET` | `/api/reports/<token>` | Report detail |
| `DELETE` | `/api/reports/<token>` | Delete |
| `GET` | `/api/reports/<token>/pdf` | PDF download |

### Admin (admin role only)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/stats` | Platform statistics + top vulns |
| `GET` | `/api/admin/scans` | All scan reports |
| `GET` | `/api/admin/users` | User list |
| `POST` | `/api/admin/users` | Create user |
| `PATCH` | `/api/admin/users/<id>` | Update role / password / target |
| `DELETE` | `/api/admin/users/<id>` | Deactivate user |
| `GET` | `/api/audit` | Audit log with filters |

---

## Deployment

### PythonAnywhere (Backend)

```bash
# In PythonAnywhere Bash console:
cd /home/<user>/finalpfe-master
git pull origin main
pip install -r backend/requirements.txt
```

Set in **Web tab → Environment variables**:
```
SECRET_KEY=<64-char random string>
FLASK_ENV=production
ALLOWED_ORIGINS=https://your-app.vercel.app
```

Set WSGI file entry point: `backend/wsgi.py` → `application`

Click **Reload**.

### Vercel (Frontend)

Set in Vercel project settings → Environment Variables:
```
VITE_API_BASE_URL=https://username.pythonanywhere.com
```

Build command: `npm run build` | Output directory: `dist`

Deploys automatically on every `git push main`.

---

## Testing

```bash
cd backend
pip install pytest pytest-cov

# All tests
pytest tests/ -v

# Coverage
pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

# Individual suites
pytest tests/test_risk_engine.py -v   # 12 tests — risk scoring
pytest tests/test_database.py -v      # 18 tests — CRUD operations
pytest tests/test_job_manager.py -v   # 10 tests — background jobs
pytest tests/test_auth.py -v          # 8 tests  — auth endpoints
pytest tests/test_api.py -v           # 12 tests — API integration
```

**Total: 60+ tests** covering risk engine, database CRUD, job manager persistence, auth flows, API endpoints, and security headers.

---

## Security

| Layer | Implementation |
|---|---|
| CSRF | Flask-WTF token on every mutation |
| Rate Limiting | Per-user, per-endpoint via Flask-Limiter |
| Password Storage | bcrypt + per-user salt |
| Session | HTTPOnly · SameSite · Secure (prod) · 30 min timeout |
| Headers | CSP nonce · HSTS · X-Frame-Options · Referrer-Policy · Permissions-Policy |
| RBAC | Admin / Analyst roles + per-permission checks on every endpoint |
| Target Locking | Analysts restricted to admin-approved targets |
| Audit Trail | IP + user-agent logged for every login, scan, and admin action |
| Input Validation | URL sanitization · extension blocklist · zip-bomb guard |

**Report vulnerabilities privately:** innovation.team.dz@gmail.com

---

## Roadmap

- [ ] TOTP / 2FA enforcement (schema ready)
- [ ] Webhook alerts (Slack / Teams / email)
- [ ] NVD CVE database integration
- [ ] GitHub Actions CI/CD scan plugin
- [ ] Multi-tenant organization accounts
- [ ] Vulnerability fix-rate trend dashboard

---

## License

MIT © 2024 HexaGuard Team
