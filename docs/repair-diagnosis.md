# HexaGuard — Repair Diagnosis

**Date:** 2026-09-24  
**Branch:** `fix/critical-repair`  
**Analyst:** Antigravity (Phase 0 read-only diagnosis)

---

## Defect 1 and 2 — Bug Bounty Radar: 0 ordinary opportunities, 0 automated-scan authorized

### Current Behaviour
The Bug Bounty Radar page (`/admin/bounty-targets`) fetches `/api/admin/bounty-targets` and gets 0 results.
Stats panel shows all zeros.

### Root Causes (proven)

**RC-1: Blueprint never registered (app.py:151-152)**
The bounty_bp blueprint is only registered when `ENABLE_LIVE_BOUNTY_SCANNING=true`.
`backend/.env` does NOT set this variable, so default is "false" and blueprint is never registered.
Every API call returns 404.

**RC-2: Deployment-mode gate blocks all routes even when registered (bounty.py:66-75)**
`enforce_bounty_local_only_gate()` returns 404 unless `DEPLOYMENT_MODE=local`.
`backend/.env` does NOT set `DEPLOYMENT_MODE`, so even if blueprint were registered, all routes return 404.

**RC-3: ALLOW classification is nearly always UNKNOWN**
`_ALLOW_TERMS` requires exact English phrases like "automated scanning allowed".
Real program policies rarely use these exact phrases; most say nothing about scanners.
Result: `_analyse_policy` returns UNKNOWN for ~95%+ records.
This produces: allowed=0, restricted=~15, unknown=tens-of-thousands.

**RC-4: Frontend correctly sends policy=ALL (no frontend bug)**

### Planned Fix (Phase 2)
1. Add `ENABLE_LIVE_BOUNTY_SCANNING=true` and `DEPLOYMENT_MODE=local` to `backend/.env`
2. Separate Bounty Radar (read-only browsing) from Live Scanning authorization:
   - Browse endpoints always available in local deployment
   - Scan-job creation blocked when ENABLE_LIVE_BOUNTY_SCANNING=false
3. Rename classification to 5-bucket model:
   DISCOVERED / AUTHORIZED_FOR_MANUAL_REVIEW / AUTHORIZED_FOR_AUTOMATED_SCANNING / UNKNOWN_AUTHORIZATION / OUT_OF_SCOPE
4. AUTHORIZED_FOR_AUTOMATED_SCANNING requires explicit affirmative evidence
5. UNKNOWN_AUTHORIZATION stays visible (not auto-scannable)
6. Frontend filter updated to new status values

---

## Defect 3 — Manual Testing page unreachable

### Current Behaviour
Route `/hunt/manual` exists in App.jsx:233 and renders ManualHuntPage correctly.
But the page is completely unreachable because:
- No sidebar link exists (ADMIN_NAV in Sidebar.jsx has no entry for /hunt/manual)
- No Learn section navigation leads there
- Users have never been able to find it

### Root Causes
- Sidebar.jsx ADMIN_NAV (lines 20-38): lists learning_tracks, skill_ledger, daily_dojo,
  vuln_library but NOTHING for manual testing
- No grouped Learn section in sidebar; all items are flat
- TracksPage.jsx is closest hub but doesn't surface Manual Web Testing
- ManualHuntPage is a static reference guide, not connected to the Track system

### Planned Fix (Phase 1)
1. Reorganize sidebar into grouped sections: Learn, Security Testing, Bug Bounty
2. Add "Manual Web Testing" link to /hunt/manual under Learn group
3. Add remaining learn items: Vulnerabilities, Tracks, Certification Prep
4. Verify ManualHuntPage renders, responds to direct URL, persists on refresh

---

## Defect 4 — Vulnerability Study and Certification Prep far below required level

### Current Behaviour
- **Vulnerability Study**: VulnLibraryPage shows catalog from vuln_taxonomy.py.
  Clicking opens LessonDetailPage. The 8-capability progression exists in db/learning.py
  and db/skills.py. curriculum.py defines 12 foundational skills with rich lesson content.
  BUT: no exercises seeded in database for these skills. Users cannot attempt lessons.
- **Certification Prep**: Does NOT exist anywhere in codebase
  (no blueprint, no frontend page, no routes, no data model)

### Root Causes
- seed_learning.py exists but exercises may not be seeded into local DB
- No /learn/certification route in App.jsx
- No certification_bp blueprint in any file
- No CertificationPage.jsx

### Planned Fix (Phases 3 and 4)
**Phase 3 (Manual Testing curriculum)**:
  Seed exercises for 3 vertical slices:
  - http_fundamentals (HTTP/session fundamentals)
  - idor (access control / BOLA)
  - xss (reflected XSS)
  All 8 capabilities for each, with real lesson/exercise content.
  Respect existing evidence semantics (theory_only, self_reported, verified_server_sandbox).

**Phase 4a (Vulnerability Study)**:
  Wire VulnLibraryPage into mastery pipeline.
  Ensure exercises are queryable and attemptable end-to-end.

**Phase 4b (Certification Prep — Security+ first)**:
  Create CertificationPage.jsx, certification_bp blueprint.
  Domain/topic/study/assessment model.
  Original Security+ content based on CompTIA SY0-701 objectives (verified from official site).
  Weak-area detection from real attempt data.
  No exam dumps; original content only.
  Never claim platform grants or officially represents the certification.

---

## Files to be changed

| Phase | File                                          | Change                                         |
|-------|-----------------------------------------------|------------------------------------------------|
| 0     | backend/.env                                   | Add ENABLE_LIVE_BOUNTY_SCANNING, DEPLOYMENT_MODE |
| 1     | frontend/src/components/Sidebar.jsx            | Grouped nav with Manual Testing link           |
| 1     | frontend/src/App.jsx                           | Routes for /learn/manual-testing, /learn/certification |
| 2     | backend/blueprints/bounty.py                   | Separate browse vs scan-auth; 5-bucket classification |
| 2     | frontend/src/pages/BountyTargetsPage.jsx       | Update policy filter to new bucket values      |
| 3     | backend/seed_learning.py                       | Seed exercises for http_fundamentals, idor, xss |
| 4     | frontend/src/pages/CertificationPage.jsx       | New page (Security+)                           |
| 4     | backend/blueprints/certification.py            | New blueprint                                  |
| 4     | backend/app.py                                 | Register certification blueprint               |

---

## Severity Summary

| # | Defect                           | Root Cause                                         | Severity    |
|---|----------------------------------|----------------------------------------------------|-------------|
| 1 | 0 ordinary bounty opportunities  | Blueprint not registered + deployment-mode gate    | CRITICAL    |
| 2 | 0 automated-scan targets         | No ALLOW_TERMS match in real policy text           | HIGH        |
| 3 | Manual Testing unreachable       | No sidebar link, no Learn section grouping         | MEDIUM      |
| 4 | Vuln Study + Cert Prep below bar | No seeded exercises; Cert Prep does not exist      | HIGH        |
