# Week 01 — 2026-07-07 → 2026-07-13

## Objectives This Week
- [x] Establish research scope and questions
- [x] Audit existing codebase for research readiness
- [x] Define the multi-dimensional risk scoring algorithm
- [x] Set up initial project structure

## Work Done

### Architecture Decisions
- Chose Flask over FastAPI (see ADR-001)
- Chose SQLite in WAL mode for development (see ADR-002)
- Designed the multi-dimensional scoring pipeline (see ADR-003)

### Code Changes
- **Created**: `backend/risk_engine.py` (v1.0) — initial multi-dimensional scorer
- **Created**: `backend/scanners/web_scanner.py` — HTTP header and content analysis
- **Created**: `backend/scanners/ssl_scanner.py` — TLS/SSL configuration analysis

### Observations
- The CVSS-only approach correctly classifies critical/low cases but consistently
  misclassifies "medium" findings that are on internet-facing PII systems
- Initial scoring weights were too conservative — RCE findings on internal systems
  scored "high" when they should be "critical" (fixed by adding context multipliers)

## Open Questions
- How to handle KEV integration without internet access in test environments?
- What is the right weight for `has_payment` vs `has_pii`?

## Decisions Made
- Use synthetic dataset first (see ADR-005) — real-world data requires 90-day window
- Implement KEV with an offline fallback (empty set) for test environments

## Next Week Plan
- [x] Implement DAST scanner
- [x] Design the initial ground truth dataset (50 cases)
- [x] Set up pytest infrastructure
