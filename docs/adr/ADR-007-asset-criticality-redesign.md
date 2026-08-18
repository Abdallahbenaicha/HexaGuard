# ADR-007 — Asset Criticality Component: Zero Measured Contribution on E1

**Status:** DRAFT — not accepted
**Date:** 2026-08-18
**Author:** Abdallah Benaicha
**Supersedes:** Nothing — new ADR
**Related:** [ADR-006 Floor Calibration](ADR-006-floor-calibration.md), esults/ablation/ablation_results.json

---

## Context

The ablation study (esearch/ablation_study.py, commit 2026-07-30) measures
the Macro-F1 contribution of each engine component by masking it and observing
the change in classification accuracy on the E1 benchmark (50 single-finding entries).

The result for sset_criticality is:

`
component: no_asset_criticality
macro_f1:  0.5942  (identical to full engine 0.5942)
delta:     0.0000
contribution: 0.0000
`

The contribution is exactly zero — not approximately zero. This ADR documents
the root-cause investigation and proposes design options for human decision.
**No scoring logic is changed by this ADR.**

---

## Observed Finding (factual)

On the current E1 dataset, removing the sset_criticality component produces
**zero measured impact** on Macro-F1. This is a measurement on a specific 50-entry
dataset; it is not a claim about the component's value in general.

---

## Root Cause Analysis

### Step 1 — E1 data loading

esearch/run_experiment.py (lines 163–173) maps sset_criticality string values
to floats via _crit_map and stores the result as kwargs["criticality"].

The ablation mask forces criticality = 0.75 (neutral/medium multiplier). Because
most E1 entries already have sset_criticality = "medium" (which maps to 0.75),
the mask changes nothing for those entries. For entries with other criticality
levels, the mask changes the kwarg but whether this matters depends on downstream logic.

### Step 2 — Engine Step 5 (multiplicative application)

In ackend/risk_engine.py (approximately lines 398–404), criticality enters
as a multiplicative environmental factor:

`python
env_mult  = max(0.1, min(float(criticality), 1.0))
env_score = temporal_score * env_mult
`

This produces an env_score that is proportional to criticality. However, env_score
is subsequently passed to Step 6.

### Step 3 — Engine Step 6 (floor guarantee)

ackend/risk_engine.py (approximately lines 417–432) applies floor guarantees:

`python
final_score = max(env_score, floor_value)
`

where loor_value is determined by the finding's severity and context
(e.g. internet_facing=True + severity="critical" → floor = 9.0).

On most E1 entries — particularly single-finding scenarios with high/critical
severity and internet exposure or known exploits — the computed floor value
exceeds the env_score regardless of the criticality multiplier. The max()
operation therefore returns the floor value for both the full-engine run and
the ablated run, producing identical risk tiers.

### Why exactly 0.000 (not small but non-zero)

No E1 entry is in a region where:
- criticality variation changes env_score across a tier boundary threshold, AND
- env_score is above the floor value (so the floor does not override it).

This is a structural property of the **current E1 dataset composition**, not a
proven property of the component in all datasets. In particular:

- Multi-finding scenarios (E2) may have different floor dynamics.
- Entries with low/medium severity may be in a regime where the floor does not
  dominate and criticality variation would cross tier boundaries.

---

## Scope Limitation

> This finding applies to the E1 single-finding dataset (50 entries, 2026-07-30
> snapshot). It does not prove that sset_criticality has zero contribution
> on all datasets or in all operational contexts. The component is not useless —
> it is unobservable on this specific dataset due to floor guarantee dominance.

---

## Design Options (for human decision — no implementation here)

### Option 1: Remove the criticality multiplier entirely

**Rationale:** If it has no measurable effect on the current evaluation, Occam's
razor suggests removing it to simplify the model.

**Risk:** Removes a theoretically justified component (asset valuation is a
recognised risk factor in NIST SP 800-37r2, FAIR). Its absence may harm performance
on other datasets not yet tested.

**Verdict:** NOT recommended without further empirical evidence across diverse datasets.

### Option 2: Apply criticality bonus after floor clamping

**Rationale:** Reorder the pipeline so Step 6 (floor) runs first, then criticality
multiplier is applied to the post-floor score. This ensures criticality always
influences the final score, even when the floor would otherwise dominate.

**Implication:** Changes the engine's mathematical contract. Requires new ADR and
full regression test. May improve ablation contribution at the cost of floor
guarantee semantics.

### Option 3: Replace multiplicative criticality with additive bonus

**Rationale:** An additive bonus (inal_score + criticality_bonus) is always
non-zero regardless of floor. This would guarantee measurable contribution on any
dataset.

**Implication:** Breaks current score normalisation. Requires recalibration of
all thresholds and floor values. Large scope change.

---

## Recommendation

Do not implement any of the above options until:
1. E2 ablation results are available (multi-finding scenarios may reveal
   criticality contribution that E1 cannot)
2. A sensitivity analysis is run across criticality values {0.2, 0.5, 0.75, 1.0}
   on both E1 and E2 to characterise the actual parameter sensitivity

---

## Amendment Policy

This ADR may be amended to:
- Add E2 ablation evidence
- Record the selected design option and its rationale

No change to isk_engine.py scoring logic is authorised by this DRAFT.