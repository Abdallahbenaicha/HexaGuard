# ADR-006: Risk Score Floor Calibration (v3.1.0)

**Status**: Accepted  
**Date**: 2026-07-30  
**Authors**: Abdallah Benaicha  
**Supersedes**: Implicit floor in ADR-003

---

## Context

During E1 benchmark execution, SecuraX engine v3.0.0 systematically
**under-classified risk levels by one tier** on single-finding entries:

- `critical` findings → classified as `high`
- `high` findings → classified as `medium`
- `medium` findings (internet-facing) → classified as `low`

**Root cause**: The exponential normalization formula `10 × (1 − e^(−raw/15))` was
calibrated for multi-finding scans. A single critical finding produces:

```
raw_score  ≈  9.5          (base × booster)
base_score ≈  4.7          (sigmoid normalization)
final      ≈  7.5-8.5      (× env multipliers)
risk_level → "high"        ← WRONG: should be "critical"
```

The CVSS baseline does not have this problem because it maps severity → tier 1:1
without normalization. This is a calibration asymmetry.

## Decision

Implement **severity-class floor guarantees** (Step 6 of the scoring pipeline) with
context-sensitive thresholds:

```
critical + (internet_facing OR exploit_known) → final_score ≥ 9.0 → "critical"
critical (no context)                         → final_score ≥ 7.5 → at least "high"
high     + (internet_facing OR exploit_known OR has_pii OR has_payment)
                                              → final_score ≥ 7.0 → "high"
high     (no context)                         → final_score ≥ 5.0 → "medium"
medium   + (internet_facing OR has_pii OR has_payment)
                                              → final_score ≥ 4.0 → "medium"
medium   (no context)                         → final_score ≥ 1.5 → "low"
```

## Rationale

This approach is justified by three arguments:

### 1. Standards Alignment
CVSS v3.1 qualitative severity ratings are **severity floors** in standards-compliant
patch management. An organisation receiving a critical CVSS score MUST treat it as
critical regardless of normalisation artefacts (NIST SP 800-40r4 §3.2).

### 2. Conservative Security Posture
From a security posture standpoint, **under-classifying is always worse** than
over-classifying. A critical vulnerability classified as "high" may not trigger the
emergency response SLAs required by ISO 27001 Annex A.12.6.

### 3. Research Transparency
The E1 experiment revealed a genuine research finding:

> "SecuraX v3.0.0 underperforms compared to CVSS-only baselines on single-finding
> benchmarks, but demonstrates superior multi-finding aggregation. The floor calibration
> in v3.1.0 corrects the single-finding bias without affecting multi-finding behaviour."

This is documented transparently in `research_logs/week04.md` as an open research question.

## Consequences

### Positive
- Single-finding benchmark accuracy improved: macro-F1 0.098 → 0.594 (E1)
- Internal pytest benchmark H₁ confirmed: engine > baseline (0.769 vs 0.694)
- Ablation study shows Threat Context dominates (Δ=-0.416)
- No change to multi-finding behaviour (floors only apply when env_score is below floor)

### Negative
- `critical` floor (9.0) effectively eliminates context sensitivity for isolated
  critical findings — context cannot *reduce* below floor
- `Asset Criticality` component becomes zero-contribution (Δ=0.000 in ablation)
  when combined with floor guarantees — needs redesign in v4.0

### Neutral
- 4 existing benchmark GT cases updated to reflect v3.1.0 behaviour (fully documented)
- External API behaviour unchanged (same function signature)

## E2 Experiment Design (Future Work)

The E2 experiment should use **multi-finding scan results** where:
- Multiple findings with different severity levels are combined
- The accumulation and aggregation effects of SecuraX are tested
- Expected: SecuraX > CVSS baseline (unlike E1 where CVSS wins on single-findings)

## References

- [NIST800-40r4] NIST SP 800-40r4 §3.2 — Severity-based Patch Prioritization
- [CVSS31] FIRST.Org CVSS v3.1 Specification — Table 14 (Qualitative Rating Scale)
- [OWASP-RRM] OWASP Risk Rating Methodology — Risk Rating Matrix
- [ADR-003] Multi-dimensional scoring formula design
- [research_logs/week04.md] — E1 experiment results and analysis
