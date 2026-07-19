<div align="center">

<img src="https://img.shields.io/badge/HexaGuard-v2.0-00f5ff?style=for-the-badge&labelColor=0a0a1a" alt="HexaGuard Version"/>

# 🛡️ HexaGuard

### Unified Cybersecurity Scanning & Intelligence Platform

*All-in-one, production-grade security assessment for SMBs and security teams — combining 11 scanner engines, AI-powered analysis, and compliance mapping in a single dashboard.*

<br/>

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-60%2B%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](#testing)
[![i18n](https://img.shields.io/badge/i18n-Arabic%20%2F%20English-f59e0b?style=flat-square)](https://en.wikipedia.org/wiki/Internationalization_and_localization)

<br/>

[📖 Architecture](#architecture) · [🚀 Quick Start](#quick-start) · [🗺️ Roadmap](#roadmap) · [🔐 Security Policy](#security-policy) · [📧 Contact](#contact)

</div>

---

## 🎯 The Problem

Modern organisations face a **fragmented security landscape**:

- 🔴 **Enterprise tools are too expensive** — Commercial SIEM platforms and managed detection services are out of reach for most SMBs.
- 🔴 **Isolated tools create blind spots** — Teams run Nmap for networks, a separate scanner for web headers, and another for code review. No shared context, no unified risk score.
- 🔴 **Slow time-to-remediation** — The industry average is measured in *weeks*. Developers cannot understand the finding, managers cannot prioritise it, and guidance is buried in a 40-page PDF.
- 🔴 **Compliance is not optional** — GDPR, PCI-DSS, and ISO 27001 carry legal liability, yet most teams lack tooling to assess compliance continuously.

## ✅ The Solution

**HexaGuard** is a self-hosted, open-source security platform that centralises every phase of a security assessment cycle:

> **Discovery → Analysis → Prioritisation → Remediation → Compliance Reporting**

It orchestrates the world's most trusted open-source security tools — OWASP ZAP, Nmap, Bandit, Semgrep, Nikto — through a single cohesive interface, then layers **ARIA**, an AI agent powered by Google Gemini 1.5, to transform raw scan data into actionable intelligence: attack chains, MITRE ATT&CK mappings, compliance assessments, and copy-pasteable remediation code.

---

## ✨ Features

### 🔍 11 Integrated Scanner Engines

| # | Scanner | Engine(s) | Coverage |
|---|---------|-----------|----------|
| 1 | **Web Application** | `requests` HTTP passive | Security headers, cookies, HTTPS redirect, server fingerprinting |
| 2 | **DAST (Dynamic)** | OWASP ZAP · Nikto · Nuclei | Active injection testing — XSS, SQLi, CSRF |
| 3 | **SAST (Static)** | Bandit · Semgrep · Gitleaks | Python, JS, multi-language source code review |
| 4 | **Network & Ports** | Nmap | Port scan, service version detection, OS fingerprinting |
| 5 | **SSL / TLS** | Python `ssl` + ASN.1 | Certificate chain, protocol versions, cipher suites |
| 6 | **Dependencies** | OSV.dev API · pip-audit · npm audit | CVE detection in Python & Node.js packages |
| 7 | **Server Config (White-box)** | Custom Apache analyser | `httpd.conf` misconfigurations + auto-generated patched config |
| 8 | **Server (Black-box)** | HTTP probing | Banner grabbing, version exposure, dangerous HTTP methods |
| 9 | **Docker Security** | Pure Python analysis | Dockerfile and image configuration review |
| 10 | **DNS & Email** | DNS-over-HTTPS (Cloudflare) | SPF, DKIM, DMARC, zone transfer, subdomain exposure |
| 11 | **WordPress** | HTTP probing | Plugin CVEs, version exposure, default path enumeration |

### 🤖 ARIA — Autonomous Risk Intelligence Agent

ARIA is not a chatbot bolted onto a scanner. It is an **autonomous five-stage analysis agent** that activates after every scan:

| Stage | Capability |
|-------|-----------|
| **NVD CVE Enrichment** | Queries NIST NVD API v2 in real-time for authoritative CVSS v3.1 scores |
| **MITRE ATT&CK Mapping** | Maps every finding to T-codes and tactics for adversarial context |
| **Attack Chain Generation** | Generates a realistic step-by-step compromise narrative across all findings |
| **Remediation Planning** | Prioritised fixes with copy-pasteable Python / Bash / Apache config code |
| **Compliance Assessment** | Automated GDPR Art. 32 · PCI-DSS Req. 6.3 · ISO 27001 A.14.2 mapping |

### ⚙️ Platform Capabilities

| Feature | Description |
|---------|-------------|
| **Background Scans** | Queue scans and navigate freely — browser push notifications on completion |
| **Scheduled Scans** | Daily / weekly / monthly recurring scans per user |
| **PDF Reports** | Professional export with CVSS scores, OWASP mapping, and remediation guidance |
| **Admin Dashboard** | System-wide stats, user management, 7-day vulnerability trend charts |
| **Audit Logs** | Full event trail with IP + user-agent for compliance (SOC 2 / ISO 27001) |
| **Role-Based Access Control** | Admin / Analyst / Viewer roles with per-user target locking |
| **Arabic + English UI** | Full RTL/LTR i18n with persistent language preference — rare in security tooling |
| **Dark / Light Mode** | Persistent theme preference across sessions |
| **Command Palette** | `Ctrl+K` quick navigation across all platform features |
| **TOTP / 2FA** | RFC 6238 multi-factor authentication with QR code setup flow |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend  (Vercel / Netlify)              │
│          React 19 · Vite 8 · Tailwind CSS · Framer Motion   │
│        Lucide Icons · Axios · React Router 7 · i18n         │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS REST API
┌──────────────────────────▼──────────────────────────────────┐
│                Backend  (Render / PythonAnywhere)            │
│             Flask 3.1 · Gunicorn · Python 3.11+             │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Blueprints │  │  ARIA Agent  │  │  Scanner Engines  │   │
│  │  auth/      │  │  Gemini 1.5  │  │  ZAP  · Nmap     │   │
│  │  scans/     │  │  NVD API     │  │  Bandit · Semgrep │   │
│  │  admin/     │  │  ATT&CK Maps │  │  Nikto · pip-audit│   │
│  │  reports/   │  │  CVSS Engine │  │  ssl  · dns · wp  │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
│                                                             │
│  Flask-WTF CSRF · Flask-Limiter · bcrypt · Flask-Login      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│             Database  (SQLite WAL / PostgreSQL)              │
│  users · scan_reports · scan_vulnerabilities · audit_logs   │
│  scan_jobs · scheduled_scans · migrations                   │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | Flask 3.1 — Application Factory pattern with Blueprint architecture |
| **Auth & Security** | Flask-Login · Flask-WTF (CSRF) · Flask-Limiter · bcrypt (12 rds) · pyotp |
| **AI Integration** | Google Gemini 1.5 Flash via `google-genai` SDK |
| **PDF Generation** | reportlab + arabic-reshaper + python-bidi |
| **Frontend** | React 19 + Vite 8 + Tailwind CSS 3 |
| **Animations** | Framer Motion 12 |
| **HTTP Client** | Axios |
| **Routing** | React Router 7 |

---

## 🚀 Quick Start

### Prerequisites

- Python **3.11+**
- Node.js **18+**
- Git

### 1 — Clone the Repository

```bash
git clone https://github.com/Abdallahbenaicha/HexaGuard.git
cd HexaGuard
```

### 2 — Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY to a 64-char random string:
# openssl rand -hex 32

python app.py
# → API running at http://localhost:5000
```

### 3 — Frontend Setup

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:5000" > .env.local
npm run dev
# → UI running at http://localhost:5173
```

### Default Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024!` |
| Analyst | `analyst` | `Analyst@2024!` |

> ⚠️ **Change these immediately after first login.**

---

## ⚙️ Environment Variables

### Backend (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | ✅ | — | Flask session secret (min 32 chars — use `openssl rand -hex 32`) |
| `FLASK_ENV` | — | `development` | Set to `production` on live server |
| `DB_PATH` | — | `hexaguard.db` | SQLite database file path |
| `GEMINI_API_KEY` | — | — | Google Gemini API key for ARIA AI features |
| `HEXAGUARD_ADMIN_PASSWORD` | — | `Admin@2024!` | Bootstrap admin password on first run |
| `ALLOWED_ORIGINS` | — | `http://localhost:5173` | Comma-separated CORS origins |
| `MYSQL_HOST` | — | — | Enable MySQL backend (set all four `MYSQL_*` vars) |
| `MYSQL_USER` | — | — | MySQL username |
| `MYSQL_PASS` | — | — | MySQL password |
| `MYSQL_DB` | — | `hexaguard` | MySQL database name |

### Frontend (`frontend/.env.local`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_API_BASE_URL` | ✅ | Backend base URL — no trailing slash |

---

## 📡 API Reference

### Authentication

| Method | Endpoint | Body |
|--------|----------|------|
| `POST` | `/api/login` | `{username, password}` |
| `POST` | `/api/logout` | — |
| `GET` | `/api/profile` | — |
| `POST` | `/api/2fa/verify` | `{token}` |

### Scans — Synchronous

| Method | Endpoint | Body |
|--------|----------|------|
| `POST` | `/api/scan/web` | `{url, mode}` |
| `POST` | `/api/scan/network` | `{target, mode}` |
| `POST` | `/api/scan/dast` | `{url}` |
| `POST` | `/api/scan/ssl` | `{host}` |
| `POST` | `/api/scan/server` | `{target, mode}` |
| `POST` | `/api/scan/sast` | `multipart/form-data {file}` |
| `POST` | `/api/scan/deps` | `multipart/form-data {file}` |

### Scans — Background / Async

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/async/web` | Queue web scan |
| `POST` | `/api/scan/async/network` | Queue network scan |
| `POST` | `/api/scan/async/dast` | Queue DAST scan |
| `POST` | `/api/scan/async/ssl` | Queue SSL scan |
| `POST` | `/api/scan/async/server` | Queue server scan |
| `GET` | `/api/scan/job/<id>` | Poll job status |
| `GET` | `/api/scan/jobs` | List all active jobs |

### Scheduled Scans

| Method | Endpoint | Body |
|--------|----------|------|
| `GET` | `/api/scheduled-scans` | — |
| `POST` | `/api/scheduled-scans` | `{scan_type, target, cron_expr}` |
| `PATCH` | `/api/scheduled-scans/<id>` | `{is_active: bool}` |
| `DELETE` | `/api/scheduled-scans/<id>` | — |

`cron_expr` values: `daily` · `weekly` · `monthly`

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/reports` | User report list |
| `GET` | `/api/reports/<token>` | Report detail with full ARIA analysis |
| `DELETE` | `/api/reports/<token>` | Delete report |
| `GET` | `/api/reports/<token>/pdf` | Download PDF |

### Admin *(admin role only)*

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/stats` | Platform statistics + top vulnerability trends |
| `GET` | `/api/admin/scans` | All scan reports across all users |
| `GET` | `/api/admin/users` | User list |
| `POST` | `/api/admin/users` | Create user |
| `PATCH` | `/api/admin/users/<id>` | Update role / password / approved target |
| `DELETE` | `/api/admin/users/<id>` | Deactivate user |
| `GET` | `/api/audit` | Audit log with filters and export |

---

## 🚢 Deployment

### Option A — Render *(Recommended)*

The `render.yaml` files in `backend/` and the project root are pre-configured for one-click deployment.

1. Connect your GitHub repository to [Render](https://render.com)
2. Set these environment variables in the Render dashboard:

```
SECRET_KEY=<64-char random string>
FLASK_ENV=production
ALLOWED_ORIGINS=https://your-frontend.vercel.app
GEMINI_API_KEY=<your-gemini-key>
```

### Option B — Vercel + PythonAnywhere

**Backend (PythonAnywhere):**
```bash
cd /home/<user>/HexaGuard
git pull origin main
pip install -r backend/requirements.txt
```

Set in **Web tab → Environment variables**:
```
SECRET_KEY=<64-char random string>
FLASK_ENV=production
ALLOWED_ORIGINS=https://your-app.vercel.app
```

WSGI entry point: `backend/wsgi.py` → `application` — click **Reload**.

**Frontend (Vercel):**
- Add env var: `VITE_API_BASE_URL=https://username.pythonanywhere.com`
- Build command: `npm run build` | Output directory: `dist`
- Auto-deploys on every `git push main`

### Option C — Docker

```bash
cd backend
docker build -t hexaguard-backend .
docker run -d \
  -p 5000:5000 \
  -e SECRET_KEY=<your-secret> \
  -e FLASK_ENV=production \
  hexaguard-backend
```

---

## 🧪 Testing

```bash
cd backend
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

# Individual test suites
pytest tests/test_risk_engine.py -v    # 12 tests — CVSS risk scoring engine
pytest tests/test_database.py -v       # 18 tests — database CRUD operations
pytest tests/test_job_manager.py -v    # 10 tests — background job persistence
pytest tests/test_auth.py -v           # 8 tests  — auth, TOTP, rate limiting
pytest tests/test_api.py -v            # 12 tests — API endpoint integration
```

**Total: 60+ tests** covering risk engine, database layer, background job queue, authentication flows, and API endpoints.

---

## 🔐 Security Policy

HexaGuard practices what it preaches. The platform itself is hardened according to OWASP Secure Coding Guidelines and NIST SP 800-63B.

| Layer | Implementation |
|-------|---------------|
| **CSRF Protection** | Flask-WTF CSRF token on every state-changing request |
| **Rate Limiting** | Per-user, per-endpoint — login: 10/min · scans: 5/min · AI: 20/hr |
| **Password Storage** | bcrypt (12 rounds) + per-user salt |
| **2FA / TOTP** | RFC 6238 via pyotp — QR code setup, per-user enable/disable with confirmation |
| **Session Security** | HttpOnly · SameSite=Lax · Secure (prod) · 30-minute idle timeout |
| **Security Headers** | CSP nonce · HSTS · X-Frame-Options: DENY · X-Content-Type-Options · Referrer-Policy · Permissions-Policy |
| **RBAC** | Admin / Analyst / Viewer roles + `@require_permission()` decorator on every endpoint |
| **IDOR Prevention** | Every report access verifies `user_id == current_user.id` |
| **Target Locking** | Analysts restricted to admin-approved scan targets only |
| **Account Lockout** | 5 failed attempts → 15-min lockout; timing-attack mitigation via constant-time bcrypt |
| **Audit Trail** | IP + user-agent logged for every login, scan, report view, and admin action |
| **Input Validation** | URL sanitisation · extension blocklist · ZIP bomb guard (150 MB uncompressed limit) |

### Responsible Disclosure

**Report vulnerabilities privately:** [innovation.team.dz@gmail.com](mailto:innovation.team.dz@gmail.com)

Please include a description of the vulnerability, steps to reproduce, and affected endpoint. We target a **72-hour initial response** and a **14-day patch timeline** for critical findings.

---

## 🗺️ Roadmap

### Q3 2026 — Near Term
- [ ] **Webhook Alerts** — Slack, Microsoft Teams, and email notifications on scan completion or critical findings
- [ ] **NVD CVE Local Mirror** — Scheduled sync for offline CVE enrichment
- [ ] **Mandatory 2FA Policy** — Admin-configurable enforcement of TOTP for all analyst accounts

### Q4 2026 — Mid Term
- [ ] **GitHub Actions Plugin** — CI/CD integration to trigger SAST + dependency scans on every pull request
- [ ] **Fix-Rate Trend Dashboard** — Track remediation velocity per team, target, and vulnerability class
- [ ] **SBOM Generation** — Software Bill of Materials export in CycloneDX / SPDX format

### 2027 — Long Term
- [ ] **Multi-Tenant Organizations** — Workspace isolation with per-org billing, SSO, and RBAC hierarchy
- [ ] **SIEM Integration** — Syslog / CEF / LEEF output for Splunk, QRadar, Elastic SIEM
- [ ] **Threat Intelligence Feeds** — Integration with OTX, MISP, and commercial threat intel sources
- [ ] **Mobile App** — React Native dashboard for scan status and critical alerts

---

## 📊 Compliance Coverage

| Standard | Scope | Assessment |
|----------|-------|-----------|
| **GDPR Art. 32** | Security of personal data processing | Critical vulns flagged as compliance violations |
| **PCI-DSS Req. 6.3** | Secure development practices | Unpatched critical/high findings fail assessment |
| **ISO 27001 A.14.2** | Secure development lifecycle | Non-conformities flagged with control references |
| **OWASP Top 10 (2021)** | Web application security | Every finding mapped to OWASP category |
| **CVSS v3.1** | Vulnerability severity scoring | Custom risk engine built on CVSS methodology |
| **MITRE ATT&CK** | Adversarial technique mapping | 30+ keywords mapped to T-codes and tactics |

---

## 🤝 Contributing

Contributions are welcome!

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/your-feature-name`
3. **Write tests** for new functionality
4. **Run the test suite**: `pytest tests/ -v`
5. **Commit** with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/): `git commit -m "feat: add webhook alert support"`
6. **Push** and open a **Pull Request**

> Never commit `.env` files, API keys, or database files. Review the security disclosure policy before submitting security-related PRs.

---

## 📁 Project Structure

```
HexaGuard/
├── backend/
│   ├── app.py                  # Application factory (create_app)
│   ├── database.py             # Database abstraction layer
│   ├── models.py               # Data models
│   ├── risk_engine.py          # CVSS v3.1 risk scoring algorithm
│   ├── ai_agent.py             # ARIA autonomous intelligence agent
│   ├── report_generator.py     # PDF report generation (Arabic + English)
│   ├── job_manager.py          # Background scan job queue
│   ├── requirements.txt
│   ├── blueprints/             # Flask blueprints (auth, scans, admin, reports)
│   ├── scanners/               # 11 scanner engine modules
│   │   ├── web_scanner.py
│   │   ├── dast_scanner.py
│   │   ├── sast_scanner.py
│   │   ├── netscan_scanner.py
│   │   ├── ssl_scanner.py
│   │   ├── dep_scanner.py
│   │   ├── server_int.py       # Custom Apache config analyser
│   │   ├── server_ext.py
│   │   ├── docker_scanner.py
│   │   ├── dns_scanner.py
│   │   └── wordpress_scanner.py
│   ├── tests/                  # 60+ pytest test cases
│   └── migrations/             # Database migration scripts
├── frontend/
│   ├── src/
│   │   ├── components/         # Reusable React components
│   │   ├── pages/              # Route-level page components
│   │   ├── hooks/              # Custom React hooks
│   │   └── i18n/               # Arabic / English translations
│   ├── package.json
│   └── vite.config.js
├── docs/                       # Extended documentation
├── render.yaml                 # One-click Render.com deployment
└── README.md
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License — Copyright © 2026 HexaGuard Team
```

---

## 📧 Contact

| Channel | Details |
|---------|---------|
| **Security Issues** | [abdallahbenaichatech@gmail.com](mailto:abdallahbenaichatech@gmail.com) *(private disclosure)* |
| **Bug Reports** | [GitHub Issues](https://github.com/Abdallahbenaicha/HexaGuard/issues) |
| **General Questions** | [GitHub Discussions](https://github.com/Abdallahbenaicha/HexaGuard/discussions) |

---

<div align="center">

Built with ❤️ by the **HexaGuard Team** — Algeria 🇩🇿

*Securing the web, one scan at a time.*

**⭐ Star this repo if HexaGuard helps your team — it helps others discover it!**

</div>
