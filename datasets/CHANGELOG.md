# SecuraX Datasets — Changelog

All notable changes to the SecuraX research datasets are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v1.0.0] — 2026-07-30

### Added
- Initial synthetic benchmark dataset (`e1_risk_validation/`)
- 5 benchmark environments (env001–env005) representing key intentionally-vulnerable targets:
  - env001: DVWA (Damn Vulnerable Web Application) — synthetic scan simulation
  - env002: OWASP Juice Shop — synthetic API vulnerability simulation
  - env003: WebGoat — synthetic authentication flaw simulation
  - env004: Metasploitable 2 — synthetic network exposure simulation
  - env005: PortSwigger Labs — synthetic API vulnerability simulation
- 50 labelled vulnerability findings across all environments
- Ground truth schema (`ground_truth.json`) with 4-tier provenance system
- Dataset manifest (`dataset-v1.0.0-manifest.json`) with SHA-256 checksums
- Placeholder structure for E2 (FPR study) and E3 (attack chain detection)

### Notes
- All v1.0.0 data is **synthetic** — constructed by domain expert to exercise
  specific risk engine code paths. See each `metadata.json` for provenance details.
- Real-world data collection is planned for v1.1.0 (DVWA lab deployment) and
  v2.0.0 (authorised real-world scans).

---

## [v1.1.0] — *planned*

### Planned Additions
- Real DVWA scan results from lab deployment
- Real JuiceShop scan results from lab deployment
- Expert-reviewed triage of FPR study (E2)

---

## [v2.0.0] — *planned*

### Planned Additions
- Authorised real-world scan results (100+ targets)
- 90-day follow-up exploitation data
- Full E1 validation dataset
- Zenodo DOI assignment
