# ADR-007 — Asset Criticality Component: Zero Measured Contribution on E1

**Status:** DRAFT — not accepted
**Date:** 2026-08-18
**Author:** Abdallah Benaicha
**Supersedes:** Nothing — new ADR
**Related:** [ADR-006 Floor Calibration](ADR-006-floor-calibration.md), `results/ablation/ablation_results.json`

---

> [!IMPORTANT]
> **DRAFT — NEEDS HUMAN REVIEW**
> This ADR is a draft investigation document only. It does NOT authorise or
> recommend any change to `backend/risk_engine.py`. No implementation has been
> performed. A human reviewer must approve any design option before implementation.

---

## Context

The ablation study (`research/ablation_study.py`, dataset snapshot 2026-07-30)
measures the Macro-F1 contribution of each engine component by masking it and
observing the change in classification accuracy on the E1 benchmark (50
single-finding entries).

The result for `asset_criticality` in `results/ablation/ablation_table.csv`:

```
no_asset_criticality,Without Asset Criticality,0.5942,0.0,0.0
```

- `macro_f1`: 0.5942 — identical to the full engine
- `delta`: 0.0000
- `contribution`: 0.0000

The contribution is exactly zero, not approximately zero. This ADR documents
the root-cause investigation and proposes design options for human decision.
**No scoring logic is changed by this ADR.**

---

## Observed Finding (factual)

- Measured: Delta = 0.000 on E1 (50-entry single-finding dataset, 2026-07-30 snapshot)
- Removing `asset_criticality` produces zero measured impact on Macro-F1
- This is a measurement on a specific dataset under specific dataset composition conditions

---

## Evidence Chain

The causal path from `asset_criticality` through to `final_score`:

### Step 1 — E1 data loading (`research/run_experiment.py` L163–165)

```python
_crit_map = {"critical": 1.0, "high": 0.9, "medium": 0.75, "low": 0.5, "minimal": 0.3}
asset_crit_str = target_meta.get("asset_criticality", "medium")
criticality_float = _crit_map.get(asset_crit_str.lower(), 0.75)
```

The ablation mask forces `criticality = 0.75` (the neutral/medium multiplier).
Most E1 entries already have `asset_criticality = "medium"` (which maps to 0.75),
so for those entries the ablation mask changes nothing. For entries with other
criticality levels, the kwarg value changes — but whether this produces a different
risk tier depends on the downstream floor guarantee logic.

### Step 2 — Engine Step 5: Environmental adjustment (`backend/risk_engine.py` L398–404)

```python
env_mult = max(0.1, min(float(criticality), 1.0))
if internet_facing: env_mult *= 1.20
if has_pii:         env_mult *= 1.15
if has_payment:     env_mult *= 1.20
env_mult *= scan_wt
env_score = round(min(temporal_score * env_mult, 10.0), 2)
```

`criticality` enters as a multiplicative factor. `env_score` is proportional to
`criticality`, but `env_score` is then passed to Step 6.

### Step 3 — Engine Step 6: Floor guarantees (`backend/risk_engine.py` L416–432)

```python
final_score = env_score
if sev_counts.get("critical", 0) > 0:
    if internet_facing or exploit_known:
        final_score = max(final_score, 9.0)   # critical tier enforced
    else:
        final_score = max(final_score, 7.5)   # at least high
elif sev_counts.get("high", 0) > 0:
    if internet_facing or exploit_known or has_pii or has_payment:
        final_score = max(final_score, 7.0)   # at least high
    else:
        final_score = max(final_score, 5.0)   # at least medium
```

On most E1 entries — single-finding scenarios with critical/high severity and
`internet_facing=True` or `exploit_known=True` — the floor value (7.0, 7.5, or 9.0)
exceeds `env_score` regardless of the `criticality` multiplier. The `max()`
returns the floor for both the full-engine and ablated runs, producing identical
risk tiers.

### Worked Representative Example

E1 entry: `severity=critical`, `internet_facing=True`.
Comparing `criticality=1.0` (full engine) vs `criticality=0.75` (ablation mask).

Assume `temporal_score = 7.0`, `scan_wt = 1.0`, no PII, no payment:

| Step | Full engine (`crit=1.0`) | Ablated (`crit=0.75`) |
|---|---|---|
| `env_mult` | 1.0 × 1.20 = 1.20 | 0.75 × 1.20 = 0.90 |
| `env_score` | 7.0 × 1.20 = **8.40** | 7.0 × 0.90 = **6.30** |
| Floor applied | max(8.40, 9.0) = **9.0** | max(6.30, 9.0) = **9.0** |
| `risk_level` | **critical** | **critical** |

Both produce `final_score = 9.0` → `"critical"`. The floor overrides the
criticality difference before tier assignment.

---

## Why Exactly 0.000 (not small but non-zero)

No E1 entry is simultaneously in a region where:

1. The criticality variation changes `env_score` across a tier threshold boundary, **AND**
2. `env_score` exceeds the floor value (so the floor does not override the `env_score`).

Both conditions must hold for criticality to have any observable effect on the
risk tier. On the current E1 dataset composition, no entry satisfies both.

---

## Scope Limitation

> **This finding applies to the E1 single-finding dataset (50 entries, 2026-07-30
> snapshot) only.**
>
> It does NOT prove that `asset_criticality` has zero contribution on all datasets
> or in all operational contexts. The component is not useless — it is unobservable
> on this specific dataset due to floor guarantee dominance in the critical/high
> severity + internet-facing scenarios that dominate E1.
>
> Multi-finding scenarios (E2) or low/medium severity entries without internet
> exposure may be in a regime where the floor does not dominate and criticality
> variation would cross tier boundaries.

---

## Design Options (for human decision — no implementation here)

### Option 1: Remove the `criticality` multiplier entirely

**Rationale:** If it has no measurable effect on the current evaluation, Occam's
razor suggests removing it to simplify the model.

**Risk:** Removes a theoretically justified component (asset valuation is a
recognised risk factor in NIST SP 800-37r2, FAIR). Its absence may harm performance
on other datasets not yet tested.

**Verdict:** NOT recommended without further empirical evidence across diverse datasets.

### Option 2: Apply criticality after floor clamping

**Rationale:** Reorder the pipeline so Step 6 (floor) runs first, then the
`criticality` multiplier is applied to the post-floor score. This ensures
criticality always influences the final score, even when the floor dominates.

**Implication:** Changes the engine's mathematical contract. Requires a new ADR,
new benchmark ground truth, and full regression test. May improve ablation
contribution at the cost of floor guarantee semantics.

### Option 3: Replace multiplicative criticality with additive bonus

**Rationale:** An additive bonus (`final_score + criticality_bonus`) is always
non-zero regardless of floor value. This would guarantee measurable contribution
on any dataset.

**Implication:** Breaks current score normalisation. Requires recalibration of
all thresholds and floor values. Large scope change.

---

## Recommendation

Do not implement any of the above options until:
1. E2 ablation results are available to determine whether criticality contribution
   is non-zero on multi-finding scenarios
2. A sensitivity analysis is run across criticality values `{0.2, 0.5, 0.75, 1.0}`
   on both E1 and E2

---

## Amendment Policy

This ADR may be amended to:
- Add E2 ablation evidence
- Record the selected design option and its rationale

No change to `risk_engine.py` scoring logic is authorised by this DRAFT.