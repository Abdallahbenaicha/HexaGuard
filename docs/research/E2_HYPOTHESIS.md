# E2 — Multi-Finding Aggregation Benchmark
## Pre-Registration Document

> **Status**: PRE-REGISTERED  
> **Committed**: 2026-07-31 (before any implementation)  
> **Experiment ID**: E2  
> **Supersedes**: Old "E2 FPR Study" (renumbered to E-FPR; see RESEARCH_ROADMAP.md)

---

## Why E2 Exists — The E1 Design Mismatch

E1 (single-finding classification) showed that Baseline-CVSS (macro-F1 = 0.800)
outperforms SecuraX (macro-F1 = 0.594) on single-finding inputs.

**This result is expected, not anomalous.** The reason is a structural mismatch
between the evaluation protocol and the engine's design:

- **What E1 measures**: Can the engine classify the risk of ONE finding in
  isolation, given environmental context?
- **What SecuraX was designed for**: Multi-finding aggregation — the score for a
  scan with 8 findings is NOT the same as the score of the worst individual
  finding. Accumulation, decay, and attack-chain correlation are meaningless when
  applied to a single finding.

The analogy: Testing a compiler optimizer only on single-instruction programs.
A naive "no-op" optimizer would be identical in performance. The optimizer's value
only appears when the input contains multiple interdependent operations.

**Baseline-CVSS on single findings is essentially the ground truth by
construction** in E1: the GT was labeled by expert elicitation using CVSS
severity as the primary signal, with no multi-finding interaction effects.

---

## Pre-Stated Hypotheses

These hypotheses are committed to git BEFORE any E2 data is created or any
E2 experiment is run. They cannot be modified after this commit.

### H0 (Null Hypothesis)

> In multi-finding scan scenarios containing 3 or more correlated vulnerability
> findings per target, SecuraX's context-aggregation engine does NOT produce
> higher macro-F1 than Baseline-CVSS (the naive severity-lookup baseline).
>
> Formally: macro-F1(SecuraX, E2) ≤ macro-F1(Baseline-CVSS, E2)

### H1 (Alternative Hypothesis)

> SecuraX's multi-finding accumulation mechanism (geometric-decay aggregation,
> contextual amplification, and attack-chain detection) produces measurably
> higher macro-F1 than Baseline-CVSS when inputs contain 3 or more correlated
> findings.
>
> Formally: macro-F1(SecuraX, E2) > macro-F1(Baseline-CVSS, E2)

### Directional prediction (not a hypothesis — an explicit design claim)

We predict that SecuraX will specifically outperform Baseline-CVSS on:
1. **Accumulation scenarios**: Multiple medium findings that collectively warrant
   a "high" classification due to attack surface breadth
2. **Attack-chain scenarios**: Co-present findings that together enable a
   multi-step exploitation path that no single finding enables alone
3. **KEV-amplified scenarios**: A medium finding that escalates to "critical"
   due to a known exploit combined with internet exposure

We predict that Baseline-CVSS will outperform SecuraX (or tie) on:
1. **Isolated critical findings**: A single critical finding that overwhelms
   all context (floor guarantee behavior — both classify as critical)
2. **Homogeneous low-severity scans**: All findings in the same tier, no
   accumulation or chain effects

---

## E2 Evaluation Protocol

### Dataset Design

- **20 multi-finding scan scenarios** (3–12 findings per scenario)
- **5 risk classes**: minimal, low, medium, high, critical
- **Class distribution**: 4 minimal, 4 low, 5 medium, 5 high, 2 critical
  (rationale: critical scenarios require multiple severe findings — rare by design)
- **Ground truth**: Scenario-level risk, expert-elicited by reasoning about
  the combined effect of all findings together (NOT per-finding)
- **Provenance**: Documented in `datasets/e2_multi_finding/metadata.json`
- **Version**: v1.0.0

### Scenario Construction Rules

1. Each scenario is a `scan_input` dict with multiple entries in the `findings`
   list (same structure as E1 but with N ≥ 3 findings)
2. The ground truth label is assigned BEFORE running any engine against the
   scenario — ground truth does not change when engine changes
3. Each scenario must have a rationale documenting which findings drive the
   expected risk level and why
4. Attack-chain scenarios must reference documented MITRE ATT&CK technique
   combinations (e.g., T1059 + T1110 = credential-access after code execution)

### Evaluation Metrics

Same as E1:
- Per-class precision, recall, F1
- Macro-F1 (primary metric — unweighted average across 5 classes)
- Confusion matrix (5×5)

### Statistical Significance

Given N=20 (small sample), we will report:
- Effect size (Cohen's d or Cliff's delta for ordinal classifiers)
- Bootstrap 95% confidence intervals (1000 resamples)
- We will NOT claim statistical significance if CIs overlap zero

### Comparison Methods

Same 4 baselines as E1:
- Baseline-CVSS (takes the worst severity present in the finding list)
- Baseline-RULE (counts + internet_facing)
- Baseline-PRIORITY (CVSS + asset_criticality)
- Baseline-RANDOM (seed=42)

### Reproducibility

```bash
python research/run_experiment.py --experiment e2 --seed 42
```

Results will be committed to `results/e2_multi_finding/` including:
- `metrics_summary.json`
- `confusion_matrix_<method>.csv` (one per method)
- `paper_tables/` (LaTeX)
- `plots/` (PNG figures)

---

## What Would Falsify H1

H1 is falsified if, after running the full E2 protocol:
- SecuraX macro-F1 ≤ Baseline-CVSS macro-F1, AND
- The bootstrap CI for the difference includes zero

If H1 is falsified:
1. We do NOT modify the ground truth
2. We do NOT re-run with different parameters to get a better result
3. We report the falsification result with full analysis of which scenario
   types caused the failure
4. We revise the engine's weight calibration based on the error analysis,
   document the revision in an ADR, and re-run as a new experiment (E2b)

---

## Relationship to PhD Research Program

This experiment directly operationalizes the core claim of the research:
that automated contextual reasoning over multi-finding evidence produces
better risk prioritization than single-signal heuristics. The methodology —
pre-registration, structured ground truth, reproducible runner — is designed
to meet the standard of a peer-reviewed systems security venue (USENIX
Security, IEEE S&P, CCS).

---

## Amendment Policy

This document may NOT be amended after its initial git commit except to:
1. Add clarifications that do not change the hypotheses or evaluation protocol
2. Record the actual results (in a clearly marked "Results" section added post-hoc)

Any change to hypotheses or protocol must be a new experiment (E2b, E2c, etc.)
with a new pre-registration document.

---

*Pre-registered by: Abdallah Benaicha*  
*Date: 2026-07-31*  
*Commit: see git log*
