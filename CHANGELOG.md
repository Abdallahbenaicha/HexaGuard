# Changelog

All notable changes to SecuraX are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned (Q3 2026)
- Webhook alerts for Slack, Teams, and email on scan completion or critical findings
- NVD CVE local mirror with scheduled sync for offline CVE enrichment
- Mandatory 2FA policy configurable per-organisation by admin

---

## [3.0.0] -- 2026-08-01

### Research (PhD admission + contribution)
- **E2 Pre-Registration** `docs/research/E2_HYPOTHESIS.md`: H0/H1 hypotheses
  committed before any implementation — methodological guardrail enforced.
- **E2 Dataset** `datasets/e2_multi_finding/`: 20 multi-finding scenarios
  (3-12 findings each), expert-elicited scenario-level ground truth.
- **E2 Results** `results/e2_risk_validation/`: H1 confirmed — SecuraX
  macro-F1 (0.5167) > Baseline-CVSS (0.3391), +52.5% relative improvement.
  `python research/run_experiment.py --experiment e2 --seed 42`
- **CISPA Research Statement** `papers/cispa_research_statement.md`: 1-page
  statement for Prof. Abbasi's group with E1+E2 combined results.
- **RESEARCH_ROADMAP.md** rewritten with honest E1/E2 framing.
- **research_logs/week05.md**: E2 per-class analysis + known weaknesses.

### Reproducibility
- Extended `research/run_experiment.py` with E2 dispatch loader architecture.
- Both `make e1` and `make e2` now produce paper-ready outputs.

### Pruning (maintainability)
- DELETED `datasets/e2_fpr_study/`: empty placeholder, confused naming
- DELETED `datasets/e3_attack_chains/`: empty placeholder, no data
- DELETED `research/generate_manifest.py`: dead code, not in any pipeline

### Fixes
- `test_web_scanner.py`: removed unsupported `mode='passive'` kwarg; fixed
  `_make_response()` headers to `dict()` preventing MagicMock in re.search().

---

## [2.0.0] -- 2026-07-30


### Added
- **Research infrastructure**
  - `CITATION.cff` \u2014 machine-readable citation metadata (CFF v1.2.0)
  - `docs/ARCHITECTURE.md` \u2014 full system architecture documentation
  - `docs/RESEARCH_ROADMAP.md` \u2014 structured research objectives and open questions
  - `docs/RISK_ENGINE.md` \u2014 mathematical specification of the scoring pipeline
  - `docs/DATASETS.md` \u2014 dataset policy, schema, and reproducibility instructions
  - `CONTRIBUTING.md` \u2014 contribution guide with research and engineering standards
  - `backend/tests/test_risk_engine_benchmark.py` \u2014 research benchmark comparing
    the multi-dimensional engine against a naive CVSS baseline (50 ground-truth cases)
  - `backend/scanners/schema.py` \u2014 formal JSON schema for all scanner outputs

- **CI/CD (fixed and upgraded)**
  - Root-level `.github/workflows/ci.yml` \u2014 CI was previously at
    `backend/.github/workflows/ci.yml` where GitHub Actions cannot read it.
    All pushes and PRs now run the full test suite.
  - CI now installs from `requirements.txt` (not a hardcoded list)
  - Added 60% test coverage gate (`--cov-fail-under=60`)
  - Added `ruff` linter step
  - Added Docker build and smoke-test step
  - Added frontend CI workflow (`.github/workflows/frontend-ci.yml`)

- **GitHub community files**
  - `SECURITY.md` \u2014 formal security policy (required for GitHub Security Advisories)
  - `.github/PULL_REQUEST_TEMPLATE.md`
  - `.github/ISSUE_TEMPLATE/bug_report.md`
  - `.github/ISSUE_TEMPLATE/feature_request.md`
  - `.github/CODEOWNERS`

- **Risk engine (`backend/risk_engine.py`)**
  - `VERSION = "3.0.0"` constant \u2014 datasets must record engine version for reproducibility
  - Full academic references (CVSS31, NIST800, OWASP, ISO27005, FAIR, CISA-KEV)
    added to module docstring and inline to all magic-constant blocks
  - Inline rationale comments for every entry in `_SCAN_TYPE_WEIGHT` and `_TYPE_BOOSTERS`
  - `pyproject.toml` for unified Python tooling configuration (ruff, pytest markers)

- **Backend configuration**
  - `backend/pyproject.toml` \u2014 centralised tooling config for ruff, pytest, and coverage

### Fixed
- **`backend/extensions.py`**: Removed duplicate `https://securax.vercel.app` entry
  in `_DEFAULT_ORIGINS`. The runtime `set()` deduplication masked this bug silently.
- **`backend/risk_engine.py` \u2014 GDPR false-negative**:
  `_build_recommendations()` previously only emitted a GDPR recommendation when
  `has_pii=True` AND there were critical/high findings, silently missing the GDPR Art. 32
  obligation for medium-severity findings on PII-processing systems.
  The fix adds an Art. 32 recommendation for medium findings and an Art. 33
  recommendation (72-hour breach notification) for critical/high findings.
- **`.gitignore`**: Added `*.db`, `*.db-shm`, `*.db-wal` patterns.
  SQLite database files containing scan results and hashed credentials were
  previously tracked in the repository.

### Security
- Database files (`securax.db`, `hexaguard.db`, and WAL files) are now
  explicitly excluded from version control via `.gitignore`.

---

## [1.0.0] \u2014 2026-01-01

### Added
- Initial public release of SecuraX (formerly HexaGuard)
- 11 integrated scanner engines: Web, DAST (OWASP ZAP/Nikto/Nuclei), SAST
  (Bandit/Semgrep/Gitleaks), Network (Nmap), SSL/TLS, Dependencies (OSV.dev),
  Server Config (white-box Apache), Server (black-box), Docker, DNS/Email, WordPress
- ARIA autonomous risk intelligence agent (5-stage: CVE enrichment, ATT\u0026CK mapping,
  attack chain generation, remediation planning, compliance assessment)
- Multi-dimensional risk scoring engine (CVSS v3.1 base + temporal + environmental)
- CISA Known Exploited Vulnerabilities (KEV) integration with 24-hour cache refresh
- Attack chain detection for dangerous vulnerability combinations
- Background scan job queue with SQLite WAL persistence
- Role-based access control (Admin / Analyst / Viewer)
- TOTP 2FA (RFC 6238) with QR code setup
- bcrypt (12 rounds) password hashing with account lockout (5 attempts / 15 min)
- Professional PDF report generation (Arabic + English, RTL/LTR)
- Full audit log (IP + user-agent on every auth, scan, and admin action)
- React 19 + Vite 8 + Tailwind CSS 3 frontend with Arabic/English i18n
- Scheduled scans (daily/weekly/monthly)
- GDPR Art. 32/33, PCI-DSS Req. 6.3.3, ISO 27001 A.14.2, OWASP Top 10 compliance mapping
- 60+ pytest tests (risk engine, database, auth, API, job manager)
- Docker + Gunicorn production deployment
- Render.com one-click deployment configuration

[Unreleased]: https://github.com/Abdallahbenaicha/SecuraX/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/Abdallahbenaicha/SecuraX/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/Abdallahbenaicha/SecuraX/releases/tag/v1.0.0
