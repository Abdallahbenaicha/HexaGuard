# FIX_PASS_REPORT.md
## SecuraX Research Integrity Fix Pass — 2026-08-18

This report documents all tasks completed and investigations performed
during the fix pass. One section per task. All constraints respected:
- metrics_summary.json in original results/ tree: NOT modified
- Ground truth files: NOT modified
- risk_engine.py scoring logic: NOT modified
- CITATION.cff / LICENSE: NOT modified
- No files deleted

---

## T9 — EPSS Baseline [COMPLETE]

### Implementation

**New file:** `research/baselines/baseline_epss.py` (v1.0.0)

Matches the exact BaselineProtocol interface: NAME, VERSION, DESCRIPTION,
classify(), metadata(). Registered in research/baselines/__init__.py and
ALL_BASELINES list.

**Classification logic:**
- Extracts CVE IDs from scan_input["vulnerabilities"][*]["cve_ids"]
- Queries https://api.first.org/data/v1/epss for each unique CVE
- Uses maximum EPSS score across all CVEs
- Experiment-defined tier mapping:
  - EPSS >= 0.70 -> critical
  - EPSS >= 0.40 -> high
  - EPSS >= 0.10 -> medium
  - EPSS >= 0.01 -> low
  - EPSS <  0.01 -> minimal  (valid EPSS result -- NOT a CVSS fallback)
- CVSS fallback only when: (a) no valid CVE, (b) API fails, (c) CVE not in EPSS

**Coverage statistics (observation-level):**
Per-run stats (epss_observations, fallback_observations, fallback_rate,
disclosure_label) are stored in _run_stats and serialized into
metrics_summary.json via metadata() called at run_experiment.py line 641.

**Disclosure rule:** fallback_rate > 0.50 -> label "Baseline-EPSS (fallback-dominated)"

### Experiment Results

Results written to results_with_epss/ (original results/ tree untouched).

**E1 (N=50 single-finding):**
| Method | Macro-F1 | Notes |
|---|---|---|
| SecuraX | 0.5942 | |
| Baseline-CVSS | 0.8000 | |
| Baseline-RULE | 0.6643 | |
| Baseline-PRIORITY | 0.8000 | |
| Baseline-RANDOM | 0.1321 | |
| Baseline-EPSS | 0.7592 | fallback-dominated (see below) |

E1 EPSS Coverage:
- total_calls: 50
- epss_observations: 7  (14%)
- fallback_observations: 43  (86%)
- fallback_rate: 0.86
- disclosure_label: "Baseline-EPSS (fallback-dominated)"

INTERPRETATION: On E1, 86% of entries used CVSS fallback (no valid CVE IDs in
synthetic entries). Baseline-EPSS result of 0.7592 is substantially a CVSS-like
result and must be labeled "Baseline-EPSS (fallback-dominated)" in any publication.
It does NOT represent a genuine EPSS evaluation on this dataset.

**E2 (N=20 multi-finding):**
| Method | Macro-F1 | Notes |
|---|---|---|
| SecuraX | 0.5167 | ABOVE all baselines on E2 |
| Baseline-CVSS | 0.3391 | |
| Baseline-RULE | 0.3391 | |
| Baseline-PRIORITY | 0.3391 | |
| Baseline-RANDOM | 0.0900 | |
| Baseline-EPSS | 0.4338 | fallback-dominated (see below) |

E2 EPSS Coverage:
- total_calls: 20
- epss_observations: 6  (30%)
- fallback_observations: 14  (70%)
- fallback_rate: 0.70
- disclosure_label: "Baseline-EPSS (fallback-dominated)"

INTERPRETATION: On E2, 70% fallback. Baseline-EPSS (0.4338) still below SecuraX (0.5167)
even when fallback-dominated. Must be labeled accordingly in publications.

---

## T8 — Bootstrap Confidence Intervals [BLOCKED — DATA-MISSING]

### Pre-registered protocol

docs/research/E2_HYPOTHESIS.md (line 111):
> "Bootstrap 95% confidence intervals (1000 resamples)"
> "Effect size (Cohen's d or Cliff's delta for ordinal classifiers)"

Pre-registered resamples: 1,000. This must not be changed without a formal
protocol amendment.

### Data availability audit

run_experiment.py lines 629-647 write metrics_summary.json with only aggregate
metrics (tp, fp, fn per class). Per-sample predictions are computed in memory
(all_results[name]["predictions"]) but NEVER written to disk.

Existing result artifacts:
- metrics_summary.json: aggregate tp/fp/fn only
- f1.csv / precision.csv / recall.csv: class-level averages
- confusion_matrix_*.csv: 5x5 aggregate counts

None of these contain per-observation prediction vectors suitable for
sample-level bootstrap resampling.

### Why aggregate counts are insufficient

Aggregate TP/FP/FN counts cannot uniquely reconstruct the per-observation
prediction distribution. Multiple distinct prediction sequences produce
identical aggregate counts. Fabricating per-sample outcomes from aggregates
would introduce spurious structure and yield confidence intervals that do not
reflect the actual sampling variability of the experiment.

### Status

T8 is BLOCKED. No bootstrap CI was computed or fabricated.

### Path forward (two options — human decision required)

Option A (recommended for publication):
  Modify run_experiment.py to write predictions_log.json alongside metrics_summary.json:
  [{"id": "...", "predicted": "...", "ground_truth": "..."}] for all N entries.
  Re-run E1 and E2 into new output paths (results_with_ci/).
  Implement research/bootstrap_ci.py reading this new file.
  Use pre-registered 1,000 resamples. Do not touch original results/.

Option B (conservative):
  Accept T8 as BLOCKED. Report in the paper that bootstrap CI was not computed
  because per-sample predictions were not persisted in the pre-registered protocol.
  Add prediction logging to run_experiment.py for future experiments only.

### Minimum code change for Option A

In run_experiment.py, after line 647 (metrics_summary.json is written), add:
  preds_log = [{"id": e.get("id", i), "predicted": all_results["SecuraX"]["predictions"][i],
                "ground_truth": ground_truth[i]}
               for i, e in enumerate(entries)]
  preds_path = output_dir / "predictions_log.json"
  preds_path.write_text(json.dumps(preds_log, indent=2), encoding="utf-8")
(Then extend similarly for each baseline.)

---

## S1 — Internal Benchmark Contradiction [INVESTIGATION COMPLETE — human decision required]

### Finding

Two separate code paths test H1 ("SecuraX outperforms the naive baseline") on
two different ground-truth datasets with opposite results.

| Property | test_risk_engine_benchmark.py | run_experiment.py --experiment e1 |
|---|---|---|
| Dataset source | Inline Python (_GT + _PADDING) | File-based datasets/e1_risk_validation/ |
| Size | 50 | 50 |
| Composition | 19 hand-labelled + 31 padding (all "medium") | 5 environments, diverse severity |
| Baseline | Local _naive_baseline() (severity only) | research/baselines/baseline_cvss.py |
| Engine macro-F1 | 0.769 | 0.594 |
| Baseline macro-F1 | 0.694 | 0.800 |
| H1 verdict | PASSES | FAILS |

### Root cause of discrepancy

The 31 padding entries in the inline dataset are all expected="medium" for medium/low
web header findings. These are scenarios where SecuraX's contextual amplification
helps and where a pure severity lookup is weaker. The file-based E1 dataset has a
distribution more adversarial to SecuraX (single-finding scenarios where CVSS
direct lookup is structurally close to the ground truth by construction).

Important operationalisation distinction: The two benchmarks do not test the same
distribution. The inline benchmark was designed around engine-favorable cases;
the file-based E1 uses scenarios where CVSS directly labels the risk.

### What must NOT happen

Neither dataset should be modified to match the other.
The H1 claim in any publication must specify which dataset and operationalisation it refers to.

### Human decision required

Option A: Report both with clearly labeled scope (inline benchmark = unit test scope;
  file-based E1 = research benchmark scope). Acknowledge different operationalisations.

Option B: Deprecate the inline _GROUND_TRUTH_DATASET and align it with the file-based E1.
  Requires re-running the inline benchmark and updating its pass/fail threshold.

Option C: Redesign file-based E1 dataset to include multi-scenario variety rather than
  only single-finding scenarios where CVSS advantage is structural.

---

## S2 — Naming / URL Conflict [INVESTIGATION COMPLETE — human decision required]

### Finding

The repository has three conflicting identity claims:

| Source | Claimed name | File |
|---|---|---|
| git remote -v | HexaGuard | (canonical — actual remote) |
| README.md (line 152) | HexaGuard | README.md |
| CITATION.cff (line 26) | SecuraX | CITATION.cff |
| frontend/package.json (line 2) | securax | frontend/package.json |
| CONTRIBUTING.md (line 37) | SecuraX | CONTRIBUTING.md |
| docs/DATASETS.md (line 160) | SecuraX | docs/DATASETS.md |

The actual git remote is:
  origin  https://github.com/Abdallahbenaicha/HexaGuard.git (fetch/push)
  space   https://huggingface.co/spaces/abdallahbenaicha/hexaguard (fetch/push)

CITATION.cff and several documentation files reference a different repository:
  https://github.com/Abdallahbenaicha/SecuraX (does not match actual remote)

### Impact

If the SecuraX repository URL does not exist or is a different repository,
the CITATION.cff is incorrect. Academic citations pointing to SecuraX would
fail to resolve or resolve to wrong content.

### No changes made

No files were renamed, no CITATION.cff was modified. This is a documentation
integrity issue requiring a human canonical name decision.

### Human decision required

Choose the canonical name (HexaGuard or SecuraX) then:
- Update CITATION.cff repository-code URL
- Update CONTRIBUTING.md clone URL
- Update docs/DATASETS.md clone URL
- Optionally align frontend/package.json "name" field

---

## S3 — Asset Criticality Zero Contribution [INVESTIGATION COMPLETE — ADR-007 written]

### Finding

results/ablation/ablation_table.csv line 3:
  no_asset_criticality,Without Asset Criticality,0.5942,0.0,0.0

The asset_criticality component has exactly zero measured contribution on E1.

### Root cause

Traced through three code stages:

1. E1 loader (run_experiment.py lines 163-173): maps asset_criticality string to
   float via _crit_map. Ablation forces criticality = 0.75 (same as most entries).

2. Engine Step 5 (risk_engine.py ~line 398-404): applies criticality as
   env_mult = max(0.1, min(criticality, 1.0)), producing env_score.

3. Engine Step 6 (risk_engine.py ~lines 417-432): floor guarantee applies
   max(env_score, floor_value). On E1 critical/high-severity internet-facing
   entries, floor_value (7.5 or 9.0) exceeds env_score regardless of criticality
   multiplier. The final tier is unchanged by criticality variation.

### Scope limitation

This is a measurement on the current E1 dataset. It does not prove the component
is useless in other datasets or operational contexts. See ADR-007 for full analysis.

### Deliverable

docs/adr/ADR-007-asset-criticality-redesign.md (DRAFT status)
- Documents the observed finding separately from the structural hypothesis
- Proposes three design options for human decision
- Makes no changes to risk_engine.py

---

## Files Changed Summary

| File | Action | Task |
|---|---|---|
| research/baselines/baseline_epss.py | NEW | T9 |
| research/baselines/__init__.py | MODIFIED (add epss) | T9 |
| results_with_epss/e1_risk_validation/ | NEW directory (full run) | T9 |
| results_with_epss/e2_risk_validation/ | NEW directory (full run) | T9 |
| docs/adr/ADR-007-asset-criticality-redesign.md | NEW (DRAFT) | S3 |
| FIX_PASS_REPORT.md | NEW (this file) | All |

## Files NOT Changed (as required)

| File | Why protected |
|---|---|
| results/e1_risk_validation/metrics_summary.json | Pre-registered results |
| results/e2_risk_validation/metrics_summary.json | Pre-registered results |
| backend/risk_engine.py | No scoring logic changes authorised |
| CITATION.cff | S2 requires human decision first |
| datasets/*/ground_truth.json | Ground truth immutable |
| LICENSE | Not in scope |