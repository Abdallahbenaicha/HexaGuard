# Week 03 — 2026-07-21 → 2026-07-27

## Objectives This Week
- [x] Complete all 11 scanner engines
- [x] Implement ARIA AI remediation agent (Gemini 1.5)
- [x] Create research benchmark (test_risk_engine_benchmark.py)
- [x] First successful benchmark run

## Work Done

### Experiments Run

| Experiment | Command | Result |
|-----------|---------|--------|
| First benchmark run | `pytest tests/test_risk_engine_benchmark.py -v -m benchmark` | Engine F1 > Baseline ✅ |
| Full test suite | `pytest tests/ -v` | 47/52 passed |

### First Benchmark Results (v3.0.0)

```
SecuraX Engine macro-F1:  0.8923
Naive CVSS baseline F1:   0.7401
Delta:                    +0.1522 (H₁ supported ✅)

Per-class:
  minimal  engine=1.000  baseline=0.941
  low      engine=0.941  baseline=0.667
  medium   engine=0.918  baseline=0.916
  high     engine=0.857  baseline=0.667
  critical engine=1.000  baseline=0.667
```

**Interpretation**: The multi-dimensional engine is particularly better at classifying
**low** (0.941 vs 0.667) and **critical** (1.000 vs 0.667) cases, confirming that
KEV and exploit_known flags add real value.

### Critical Finding — Medium class
Medium class F1 is nearly identical (0.918 vs 0.916). The engine does not add
significant value over CVSS-only for medium findings. This may indicate:
1. Medium findings rarely have exploit_known=True (KEV is less useful here)
2. Environmental context (internet_facing) does not clearly differentiate medium

**Action**: Add medium-specific test cases to the ablation study.

### Code Changes
- **Created**: `backend/ai_agent.py` — ARIA Gemini integration
- **Created**: `backend/tests/test_risk_engine_benchmark.py` — research benchmark
- **Modified**: `backend/risk_engine.py` (v3.0.0) — attack chain detection added

### Observations
- ARIA remediation quality is high for injection vulnerabilities, weaker for
  configuration issues (missing headers) — likely due to training data bias
- The 50-case ground truth dataset is not balanced:
  - 31/50 cases are "medium" (padding) — this inflates medium F1 for both methods
  - Future datasets need better class balance

## Open Questions
- Should the padding cases be removed? → They inflate medium class artificially
- Better to use a stratified sample of real findings

## Decisions Made
- Keep padding cases for now (transparency via WARNING in benchmark docstring)
- Plan stratified sampling for v1.1.0 dataset

## Next Week Plan
- [x] Add research infrastructure (datasets/, research/, papers/)
- [x] Create Plugin SDK
- [x] Ablation study
- [x] Documentation (ADRs, Threat Model, PLUGIN_SDK.md)
