# Week 02 — 2026-07-14 → 2026-07-20

## Objectives This Week
- [x] Implement DAST scanner with active probing
- [x] Design and implement SAST scanner (static code analysis)
- [x] Integrate CISA KEV catalog with background refresh thread
- [x] Create first version of ground truth dataset (20 cases)

## Work Done

### Experiments Run
| Test | Command | Result |
|------|---------|--------|
| Risk engine basic test | `pytest tests/test_risk_engine.py -v` | 12/12 passed |
| KEV integration test | `pytest tests/ -k "kev" -v` | 3/3 passed |

### Code Changes
- **Created**: `backend/scanners/dast_scanner.py` — active web probing
- **Created**: `backend/scanners/sast_scanner.py` — regex-based static analysis
- **Modified**: `backend/risk_engine.py` (v1.5) — added KEV background thread

### KEV Integration Design
The KEV integration uses a background daemon thread that refreshes every 24 hours:
```python
_kev_background_worker() → threading.Thread(daemon=True)
```

**Failure mode**: If CISA API is unreachable, the KEV cache is empty (not stale).
This means findings are NOT falsely upgraded — conservative failure.

### Observations
- SAST regex patterns have high false positive rate for hardcoded secrets
  (catches test data, comments, etc.)
- Decision: SAST findings should be reviewed by analyst, not auto-escalated
- KEV lookup adds ~2ms per finding (acceptable)

## Open Questions
- Should SAST FP rate be documented in the benchmark? → Yes, E2 experiment
- How to handle SSL scanner on sites with self-signed certs?

## Metrics This Week
| Metric | Value |
|--------|-------|
| Scanners implemented | 4 / 11 |
| Test coverage | 67% |
| Ground truth cases | 20 / 50 |

## Decisions Made
- KEV offline fallback → empty set (conservative)
- SAST severity ceiling at "high" unless manually confirmed critical

## Next Week Plan
- [x] Complete remaining 7 scanner engines
- [x] Expand ground truth to 50 cases
- [x] Implement ARIA (AI remediation agent)
