"""
journey.py -- "How SecuraX Was Built" Blueprint

GET /api/journey          -> full ordered list of build milestones
GET /api/journey/<phase>  -> single phase detail
GET /api/journey/meta/stats -> summary counts

Zero-Schema rule: no DB tables, no migrations. Static catalogue
pattern identical to tracks.py.
"""
from __future__ import annotations
from flask import Blueprint, jsonify
from flask_login import login_required

journey_bp = Blueprint("journey", __name__, url_prefix="/api/journey")

_PHASES = [
    {
        "id": "phase-0", "order": 0, "phase": "Genesis", "emoji": "\U0001f331",
        "title_en": "Genesis \u2014 The Problem Space",
        "title_ar": "\u0627\u0644\u0628\u062f\u0627\u064a\u0629 \u2014 \u0641\u0647\u0645 \u0627\u0644\u0645\u0634\u0643\u0644\u0629",
        "date_label": "Early 2025", "status": "complete",
        "summary_en": (
            "Identified a gap: cybersecurity practitioners in the Arab world lack a single "
            "Arabic-first platform combining scanning, learning, and intelligence. "
            "SecuraX was born as the answer."
        ),
        "summary_ar": (
            "\u0631\u064f\u0635\u062f \u0641\u0631\u0627\u063a \u062d\u0642\u064a\u0642\u064a: "
            "\u0627\u0644\u0645\u062e\u062a\u0635\u0648\u0646 \u0627\u0644\u0623\u0645\u0646\u064a\u0648\u0646 \u0641\u064a \u0627\u0644\u0639\u0627\u0644\u0645 \u0627\u0644\u0639\u0631\u0628\u064a \u064a\u0641\u062a\u0642\u0631\u0648\u0646 \u0644\u0645\u0646\u0635\u0629 \u0645\u0648\u062d\u062f\u0629."
        ),
        "decisions": [
            {"key": "D-01", "text_en": "Flask + React for clean API/UI separation.", "text_ar": "Flask + React \u0644\u0641\u0635\u0644 API/UI \u0646\u0638\u064a\u0641."},
            {"key": "D-02", "text_en": "SQLite first \u2014 defer managed DB until scale demands it.", "text_ar": "SQLite \u0623\u0648\u0644\u0627\u064b \u2014 \u062a\u0623\u062c\u064a\u0644 \u0642\u0627\u0639\u062f\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u062d\u062a\u0649 \u0627\u0644\u062d\u0627\u062c\u0629."},
            {"key": "D-03", "text_en": "Arabic + English RTL/LTR support from day zero.", "text_ar": "\u062f\u0639\u0645 RTL/LTR \u0645\u0646 \u0627\u0644\u064a\u0648\u0645 \u0627\u0644\u0623\u0648\u0644."},
        ],
        "key_files": [],
        "lessons": [{"text_en": "Scope creep is the silent project killer \u2014 nail the MVP first.", "text_ar": "\u0632\u062d\u0641 \u0627\u0644\u0646\u0637\u0627\u0642 \u0647\u0648 \u0627\u0644\u0642\u0627\u062a\u0644 \u0627\u0644\u0635\u0627\u0645\u062a \u2014 \u0623\u0646\u062c\u0632 MVP \u0623\u0648\u0644\u0627\u064b."}],
        "color": "#10b981",
        "tech_tags": ["Flask", "React", "SQLite", "Vite", "Tailwind"],
    },
    {
        "id": "phase-1", "order": 1, "phase": "Scanner Engine", "emoji": "\U0001f52c",
        "title_en": "Scanner Engine \u2014 The Security Core",
        "title_ar": "\u0645\u062d\u0631\u0643 \u0627\u0644\u0641\u062d\u0635 \u2014 \u0627\u0644\u0646\u0648\u0627\u0629 \u0627\u0644\u0623\u0645\u0646\u064a\u0629",
        "date_label": "Feb 2025", "status": "complete",
        "summary_en": (
            "Built multi-scanner engine: Web App (OWASP Top-10), SSL/TLS, Network, "
            "Code SAST, DAST, Config Audit, Dependencies, Docker, DNS/Email, WordPress. "
            "Risk Engine centralises CVSS-like scoring."
        ),
        "summary_ar": (
            "\u0628\u064f\u0646\u064a \u0645\u062d\u0631\u0643 \u0627\u0644\u0641\u062d\u0635 "
            "\u0645\u062a\u0639\u062f\u062f \u0627\u0644\u0623\u062f\u0648\u0627\u062a: "
            "\u0648\u064a\u0628 (OWASP)\u060c SSL/TLS\u060c \u0634\u0628\u0643\u0629\u060c SAST\u060c DAST\u060c "
            "\u0625\u0639\u062f\u0627\u062f\u0627\u062a\u060c \u062a\u0628\u0639\u064a\u0627\u062a\u060c Docker\u060c DNS/\u0628\u0631\u064a\u062f\u060c WordPress."
        ),
        "decisions": [
            {"key": "D-04", "text_en": "Risk Engine centralises CVSS-like scoring \u2014 scanners never score themselves.", "text_ar": "\u0645\u062d\u0631\u0643 \u0627\u0644\u0645\u062e\u0627\u0637\u0631 \u064a\u064f\u0645\u0631\u0643\u0632 \u0627\u0644\u062a\u0633\u062c\u064a\u0644."},
            {"key": "D-05", "text_en": "Magic-byte check + zip-bomb guard must cover .xlsx not only .zip.", "text_ar": "\u0641\u062d\u0635 Magic-byte + \u062d\u0645\u0627\u064a\u0629 zip-bomb \u064a\u062c\u0628 \u0623\u0646 \u062a\u0634\u0645\u0644 .xlsx."},
        ],
        "key_files": ["backend/scanners/", "backend/risk_engine.py", "backend/utils.py", "backend/blueprints/scans.py"],
        "lessons": [{"text_en": "Always validate file type by magic bytes, not extension.", "text_ar": "\u062a\u062d\u0642\u0642 \u062f\u0627\u0626\u0645\u0627\u064b \u0645\u0646 \u0646\u0648\u0639 \u0627\u0644\u0645\u0644\u0641 \u0628\u0627\u0644\u0628\u0627\u064a\u062a\u0627\u062a \u0627\u0644\u0633\u062d\u0631\u064a\u0629 \u0644\u0627 \u0627\u0644\u0627\u0645\u062a\u062f\u0627\u062f."}],
        "color": "#3b82f6",
        "tech_tags": ["Python", "Nmap", "OWASP", "CVSS", "SQLite"],
    },
    {
        "id": "phase-2", "order": 2, "phase": "Learning Subsystem", "emoji": "\U0001f393",
        "title_en": "Learning Subsystem \u2014 Education Layer",
        "title_ar": "\u0646\u0638\u0627\u0645 \u0627\u0644\u062a\u0639\u0644\u0645 \u2014 \u0637\u0628\u0642\u0629 \u0627\u0644\u062a\u0639\u0644\u064a\u0645",
        "date_label": "Mar 2025", "status": "complete",
        "summary_en": (
            "Built Vulnerability Library (96 vuln types via vuln_taxonomy.py), Skill Ledger, "
            "Daily Micro-Dojo (streak challenges), Learning Tracks, Certification Prep, "
            "and interactive Sandbox labs (JuiceShop / DVWA)."
        ),
        "summary_ar": (
            "\u0628\u064f\u0646\u064a \u0645\u0643\u062a\u0628\u0629 \u0627\u0644\u062b\u063a\u0631\u0627\u062a (96 \u0646\u0648\u0639)\u060c "
            "\u0633\u062c\u0644 \u0627\u0644\u0645\u0647\u0627\u0631\u0627\u062a\u060c \u0627\u0644\u062f\u0648\u062c\u0648 \u0627\u0644\u064a\u0648\u0645\u064a\u060c "
            "\u0645\u0633\u0627\u0631\u0627\u062a \u0627\u0644\u062a\u0639\u0644\u0645\u060c \u0648\u0645\u062e\u062a\u0628\u0631\u0627\u062a Sandbox."
        ),
        "decisions": [
            {"key": "D-06", "text_en": "96-exercise contract (12 skills x 8 caps) is a CI invariant \u2014 ALTER TABLE is forbidden.", "text_ar": "\u0639\u0642\u062f 96 \u062a\u0645\u0631\u064a\u0646\u0627\u064b \u062b\u0627\u0628\u062a CI \u2014 ALTER TABLE \u0645\u062d\u0638\u0648\u0631."},
            {"key": "D-07", "text_en": "AUTHORITATIVE(1.0) only for containerised sandbox exploits; EVALUATED(0.9) otherwise.", "text_ar": "AUTHORITATIVE \u0641\u0642\u0637 \u0644\u0644\u0640 sandbox \u0627\u0644\u0645\u064f\u0639\u0632\u0648\u0644\u0629."},
        ],
        "key_files": ["backend/vuln_taxonomy.py", "backend/seed_learning.py", "backend/blueprints/tracks.py", "backend/blueprints/sandbox.py", "backend/db/exercise_engine.py"],
        "lessons": [{"text_en": "Design the invariant before schema, not after.", "text_ar": "\u0635\u0645\u0651\u0645 \u0627\u0644\u062b\u0627\u0628\u062a \u0642\u0628\u0644 \u0627\u0644\u0640 schema \u0644\u0627 \u0628\u0639\u062f\u0647."}],
        "color": "#8b5cf6",
        "tech_tags": ["SQLite", "Flask-Login", "JuiceShop", "DVWA", "Docker"],
    },
    {
        "id": "phase-3", "order": 3, "phase": "Bug Bounty & Blue Team", "emoji": "\U0001f3af",
        "title_en": "Bug Bounty Radar & Blue Team \u2014 Adversarial Layer",
        "title_ar": "\u0631\u0627\u062f\u0627\u0631 Bug Bounty \u0648\u0627\u0644\u0641\u0631\u064a\u0642 \u0627\u0644\u0623\u0632\u0631\u0642 \u2014 \u0627\u0644\u0637\u0628\u0642\u0629 \u0627\u0644\u0639\u062f\u0627\u0626\u064a\u0629",
        "date_label": "Apr 2025", "status": "complete",
        "summary_en": (
            "Added Bounty Radar (authorized scope, EPSS scoring), SOC Case Files "
            "(digital forensics, MITRE ATT&CK mapping), Manual Hunt Guide, "
            "and Attack-Chain visualisation panel."
        ),
        "summary_ar": (
            "\u0623\u064f\u0636\u064a\u0641 \u0631\u0627\u062f\u0627\u0631 Bounty\u060c \u0645\u0644\u0641\u0627\u062a \u0642\u0636\u0627\u064a\u0627 SOC "
            "(MITRE ATT&CK)\u060c \u062f\u0644\u064a\u0644 \u0627\u0644\u0635\u064a\u062f \u0627\u0644\u064a\u062f\u0648\u064a\u060c "
            "\u0648\u0644\u0648\u062d\u0629 \u062a\u0635\u0648\u0631 \u0633\u0644\u0627\u0633\u0644 \u0627\u0644\u0647\u062c\u0645\u0627\u062a."
        ),
        "decisions": [
            {"key": "D-08", "text_en": "KEV_MEMBERSHIP (bool) and KEV_CATALOG_RECORD (dict) are separate fields \u2014 never merge.", "text_ar": "KEV_MEMBERSHIP \u0648 KEV_CATALOG_RECORD \u062d\u0642\u0644\u0627\u0646 \u0645\u0633\u062a\u0642\u0644\u0627\u0646 \u2014 \u0644\u0627 \u064a\u064f\u062f\u0645\u062c\u0627\u0646."},
            {"key": "D-09", "text_en": "RULE ENGINE and ARIA AI SYNTHESIS must remain architecturally separate.", "text_ar": "\u0645\u062d\u0631\u0643 \u0627\u0644\u0642\u0648\u0627\u0639\u062f \u0648 ARIA AI \u064a\u062c\u0628 \u0623\u0646 \u064a\u0628\u0642\u064a\u0627 \u0645\u0633\u062a\u0642\u0644\u064a\u0646 \u0645\u0639\u0645\u0627\u0631\u064a\u0627\u064b."},
        ],
        "key_files": ["backend/blueprints/bounty.py", "backend/blueprints/casefiles.py", "frontend/src/components/AttackChainPanel.jsx"],
        "lessons": [{"text_en": "Feature flags let you ship code before enabling it in production.", "text_ar": "\u0623\u0639\u0644\u0627\u0645 \u0627\u0644\u0645\u064a\u0632\u0627\u062a \u062a\u062a\u064a\u062d \u0634\u062d\u0646 \u0627\u0644\u0643\u0648\u062f \u0642\u0628\u0644 \u062a\u0641\u0639\u064a\u0644\u0647."}],
        "color": "#f59e0b",
        "tech_tags": ["MITRE ATT&CK", "EPSS", "NVD", "CISA KEV", "React"],
    },
    {
        "id": "phase-4", "order": 4, "phase": "Intelligence Center", "emoji": "\U0001f9e0",
        "title_en": "Cyber Intelligence Center \u2014 Live Threat Awareness",
        "title_ar": "\u0645\u0631\u0643\u0632 \u0627\u0644\u0627\u0633\u062a\u062e\u0628\u0627\u0631\u0627\u062a \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a\u0629 \u2014 \u0627\u0644\u0648\u0639\u064a \u0628\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a",
        "date_label": "May 2025", "status": "complete",
        "summary_en": (
            "Cyber Intelligence aggregating CVE/NVD, CISA KEV, EPSS, FIRST advisories, "
            "arXiv research, EUR-Lex/NIST regulations, security tools, conferences, incidents. "
            "ARIA AI synthesizes cross-source intelligence into actionable summaries."
        ),
        "summary_ar": (
            "\u0627\u0633\u062a\u062e\u0628\u0627\u0631\u0627\u062a \u062a\u062c\u0645\u0639 CVE/NVD\u060c CISA KEV\u060c EPSS\u060c FIRST\u060c arXiv\u060c "
            "\u0644\u0648\u0627\u0626\u062d EUR-Lex/NIST\u060c \u0623\u062f\u0648\u0627\u062a\u060c \u0645\u0624\u062a\u0645\u0631\u0627\u062a\u060c \u0648\u062d\u0648\u0627\u062f\u062b. "
            "ARIA AI \u064a\u0648\u0644\u0650\u0651\u064a\u0641 \u0627\u0644\u0627\u0633\u062a\u062e\u0628\u0627\u0631\u0627\u062a."
        ),
        "decisions": [
            {"key": "D-10", "text_en": "Two-layer data model: Raw Source Layer (immutable) + Normalized Layer (derived). Never normalize at ingestion.", "text_ar": "\u0646\u0645\u0648\u0630\u062c \u062b\u0646\u0627\u0626\u064a \u0627\u0644\u0637\u0628\u0642\u0627\u062a: \u062e\u0627\u0645 + \u0645\u0648\u062d\u0651\u062f."},
            {"key": "D-11", "text_en": "Rate-limit budget: NVD 50 req/30s, FIRST 60 req/min, arXiv 3 req/s.", "text_ar": "\u062d\u062f\u0648\u062f \u0627\u0644\u0645\u0639\u062f\u0644: NVD 50/30\u062b\u060c FIRST 60/\u062f\u0642\u064a\u0642\u0629\u060c arXiv 3/\u062b."},
        ],
        "key_files": ["backend/blueprints/intelligence.py", "frontend/src/pages/IntelligencePage.jsx"],
        "lessons": [{"text_en": "External APIs have rate limits \u2014 implement exponential backoff and cache aggressively.", "text_ar": "\u0648\u0627\u062c\u0647\u0627\u062a API \u0644\u0647\u0627 \u062d\u062f\u0648\u062f \u2014 \u062c\u0631\u0651\u0628 \u0627\u0644\u062a\u0631\u0627\u062c\u0639 \u0627\u0644\u0623\u0633\u064a \u0648\u0627\u0644\u062a\u062e\u0632\u064a\u0646 \u0627\u0644\u0645\u0643\u062b\u0641."}],
        "color": "#06b6d4",
        "tech_tags": ["NVD API", "CISA KEV", "EPSS", "arXiv", "ARIA AI"],
    },
    {
        "id": "phase-5", "order": 5, "phase": "PhD Intelligence Tracker", "emoji": "\U0001f4da",
        "title_en": "Personal PhD Intelligence Tracker \u2014 Research CRM",
        "title_ar": "\u0645\u062a\u062a\u0628\u0639 \u0627\u0644\u062f\u0643\u062a\u0648\u0631\u0627\u0647 \u0627\u0644\u0634\u062e\u0635\u064a \u2014 CRM \u0627\u0644\u0628\u062d\u062b \u0627\u0644\u0639\u0644\u0645\u064a",
        "date_label": "Jun 2025", "status": "complete",
        "summary_en": (
            "Structured CRM for PhD applications, research labs, professors, funding "
            "(scholarships, fellowships, grants), publication tracking, deadline management. "
            "Ingests from two-layer XLSX pipeline."
        ),
        "summary_ar": (
            "CRM \u0645\u0646\u0638\u0645 \u0644\u0637\u0644\u0628\u0627\u062a \u0627\u0644\u062f\u0643\u062a\u0648\u0631\u0627\u0647\u060c "
            "\u0645\u062e\u062a\u0628\u0631\u0627\u062a \u0627\u0644\u0623\u0628\u062d\u0627\u062b\u060c \u0627\u0644\u062a\u0645\u0648\u064a\u0644\u060c "
            "\u0627\u0644\u0645\u0646\u0634\u0648\u0631\u0627\u062a\u060c \u0648\u0627\u0644\u0645\u0648\u0627\u0639\u064a\u062f. "
            "\u064a\u0633\u062a\u0648\u0639\u0628 \u0645\u0646 \u062e\u0637 \u0623\u0646\u0627\u0628\u064a\u0628 XLSX \u062b\u0646\u0627\u0626\u064a."
        ),
        "decisions": [
            {"key": "D-12", "text_en": "Formulas preserved as-is at rest (never evaluated or escaped at storage).", "text_ar": "\u0627\u0644\u0635\u064a\u063a \u0645\u062d\u0641\u0648\u0638\u0629 \u0643\u0645\u0627 \u0647\u064a (\u0644\u0627 \u062a\u064f\u062d\u0633\u0628 \u0648\u0644\u0627 \u062a\u064f\u0647\u0631\u064f\u0651\u0648\u064e\u0628)."},
            {"key": "D-13", "text_en": "Canada regex corrected for whitespace variants in Arabic text.", "text_ar": "\u062a\u0635\u062d\u064a\u062d regex \u0643\u0646\u062f\u0627 \u0644\u0645\u062a\u063a\u064a\u0631\u0627\u062a \u0627\u0644\u0645\u0633\u0627\u0641\u0629."},
        ],
        "key_files": ["backend/blueprints/phd.py", "frontend/src/pages/PhdTrackerPage.jsx"],
        "lessons": [{"text_en": "Never silently normalize ambiguous data \u2014 preserve provenance at all cost.", "text_ar": "\u0644\u0627 \u062a\u064f\u0648\u062d\u0651\u062f \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u063a\u0627\u0645\u0636\u0629 \u0628\u0635\u0645\u062a \u2014 \u0627\u062d\u0641\u0638 \u0627\u0644\u0633\u0646\u062f \u062f\u0627\u0626\u0645\u0627\u064b."}],
        "color": "#ec4899",
        "tech_tags": ["XLSX", "Two-Layer Model", "Flask", "React", "Arabic RTL"],
    },
    {
        "id": "phase-6", "order": 6, "phase": "Production Hardening", "emoji": "\U0001f6e1",
        "title_en": "Production Hardening \u2014 Security & Reliability",
        "title_ar": "\u062a\u0635\u0644\u064a\u0628 \u0627\u0644\u0625\u0646\u062a\u0627\u062c \u2014 \u0627\u0644\u0623\u0645\u0627\u0646 \u0648\u0627\u0644\u0645\u0648\u062b\u0648\u0642\u064a\u0629",
        "date_label": "Ongoing", "status": "in_progress",
        "summary_en": (
            "Continuous: workers=1 mandate, XLSX zip-bomb guard, rate limiting, CSRF, "
            "session hardening, Gunicorn config, and the full Gate 0/0.1 evidence audit system."
        ),
        "summary_ar": (
            "\u0645\u0633\u062a\u0645\u0631: \u062a\u0641\u0648\u064a\u0636 workers=1\u060c \u062d\u0645\u0627\u064a\u0629 zip-bomb\u060c "
            "\u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0645\u0639\u062f\u0644\u060c CSRF\u060c \u062a\u0635\u0644\u064a\u0628 \u0627\u0644\u062c\u0644\u0633\u0629\u060c "
            "\u0625\u0639\u062f\u0627\u062f Gunicorn\u060c \u0648\u0646\u0638\u0627\u0645 \u062a\u062f\u0642\u064a\u0642 Gate 0/0.1."
        ),
        "decisions": [
            {"key": "D-14", "text_en": "Workers=1 is a hard architectural constraint until Atomic DB CAS Guard is deployed.", "text_ar": "workers=1 \u0642\u064a\u062f \u0645\u0639\u0645\u0627\u0631\u064a \u0635\u0627\u0631\u0645 \u062d\u062a\u0649 \u0646\u0634\u0631 Atomic DB CAS Guard."},
            {"key": "D-15", "text_en": "Gate system (0 to 0.1 to 1) enforces read-only auditing before any build phase.", "text_ar": "\u0646\u0638\u0627\u0645 Gate \u064a\u0641\u0631\u0636 \u062a\u062f\u0642\u064a\u0642 \u0627\u0644\u0642\u0631\u0627\u0621\u0629 \u0642\u0628\u0644 \u0623\u064a \u0645\u0631\u062d\u0644\u0629 \u0628\u0646\u0627\u0621."},
        ],
        "key_files": ["backend/app.py", "backend/utils.py", "backend/middleware.py", "backend/gunicorn.conf.py"],
        "lessons": [{"text_en": "Architectural constraints must be enforced at startup, not in documentation alone.", "text_ar": "\u0627\u0644\u0642\u064a\u0648\u062f \u0627\u0644\u0645\u0639\u0645\u0627\u0631\u064a\u0629 \u064a\u062c\u0628 \u0623\u0646 \u062a\u064f\u0641\u0631\u0636 \u0639\u0646\u062f \u0628\u062f\u0621 \u0627\u0644\u062a\u0634\u063a\u064a\u0644."}],
        "color": "#ef4444",
        "tech_tags": ["Gunicorn", "Flask-Limiter", "Flask-WTF", "SQLite", "Docker"],
    },
]

_PHASE_INDEX = {p["id"]: p for p in _PHASES}


@journey_bp.route("", methods=["GET"])
@login_required
def list_phases():
    """GET /api/journey -- full ordered build journey."""
    return jsonify({"ok": True, "phases": _PHASES})


@journey_bp.route("/meta/stats", methods=["GET"])
@login_required
def journey_stats():
    """GET /api/journey/meta/stats -- summary counts."""
    total = len(_PHASES)
    complete = sum(1 for p in _PHASES if p["status"] == "complete")
    in_progress = sum(1 for p in _PHASES if p["status"] == "in_progress")
    return jsonify({"ok": True, "stats": {
        "total_phases": total,
        "complete": complete,
        "in_progress": in_progress,
        "planned": total - complete - in_progress,
        "total_decisions": sum(len(p.get("decisions", [])) for p in _PHASES),
        "total_lessons": sum(len(p.get("lessons", [])) for p in _PHASES),
    }})


@journey_bp.route("/<phase_id>", methods=["GET"])
@login_required
def get_phase(phase_id):
    """GET /api/journey/<id> -- single phase detail."""
    phase = _PHASE_INDEX.get(phase_id)
    if not phase:
        return jsonify({"ok": False, "error": f"Phase '{phase_id}' not found."}), 404
    return jsonify({"ok": True, "phase": phase})
