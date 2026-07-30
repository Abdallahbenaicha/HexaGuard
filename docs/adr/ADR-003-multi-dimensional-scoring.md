# ADR-003 — Risk Scoring: Multi-Dimensional vs CVSS-Only

**Status**: Accepted  
**Date**: 2026-02-01  
**Deciders**: Abdallah Benaicha  
**Supersedes**: N/A  
**Related**: [docs/RISK_ENGINE.md](../RISK_ENGINE.md), [RQ1 in RESEARCH_ROADMAP.md](../RESEARCH_ROADMAP.md)

---

## Context

Every vulnerability scanner must translate raw findings into a prioritisation signal.
The two dominant approaches in the literature are:

### The Research Question (RQ1)

> *Is the multi-dimensional SecuraX risk score a better predictor of actual
> vulnerability impact than a naive CVSS-only severity lookup?*

This ADR documents the design decision that makes RQ1 testable.

### Option A: CVSS-Only (Naive Baseline)

Map highest severity to risk level:

```
critical → 9.5  |  high → 7.5  |  medium → 5.0  |  low → 2.0
```

**Pros**:
- Simple and transparent
- Widely understood by practitioners
- Reproducible without additional context

**Cons**:
- Ignores exploitability (is there a public exploit?)
- Ignores exposure (is the system internet-facing?)
- Ignores business context (PII, payment data)
- Ignores compliance requirements (GDPR, PCI-DSS)
- Two equal CVSS scores in different contexts → same priority (wrong)

**Evidence against CVSS-only**:
- [Jacobs et al., 2021]: Only 3% of CVEs are ever exploited in the wild.
  CVSS does not predict which 3%.
- [CISA KEV, 2021-present]: CISA publishes a "Known Exploited Vulnerabilities"
  catalog that correlates with actual attacks, independent of CVSS score.
- [Spring et al., 2021]: EPSS (Exploit Prediction Scoring System) outperforms
  CVSS at predicting exploitation.

### Option B: Multi-Dimensional Scoring (SecuraX Engine)

```
Pipeline:
  Base score          (CVSS severity → score)
  × Exploitability    (exploit_known, KEV lookup, CVE presence)
  × Exposure          (internet_facing factor)
  × Business context  (has_pii → GDPR, has_payment → PCI-DSS)
  × Asset criticality (business value of the asset)
  + Attack chain bonus (co-occurring findings that form kill chains)
  = Final score → Risk level
```

**Pros**:
- Contextually aware — same CVE scores differently in different environments
- KEV integration ensures actively exploited vulns are always prioritised
- Compliance penalties (GDPR/PCI-DSS) align with regulatory requirements
- Attack chain detection identifies multi-step exploitation paths

**Cons**:
- More complex — requires expert calibration of weights
- Parameters (weights, multipliers) introduce researcher degrees of freedom
- Must be validated empirically against a ground-truth dataset (hence Benchmark)

---

## Decision

**Multi-dimensional scoring (SecuraX engine) is the primary scorer.**

The CVSS-only approach is retained as **Baseline-CVSS** for comparative evaluation.
The research claim is: `Engine macro-F1 > Baseline-CVSS macro-F1` on the E1 benchmark.

Weight calibration follows expert elicitation documented in `docs/RISK_ENGINE.md`.

---

## Consequences

### Positive
- Contextually accurate risk prioritisation
- Regulatory compliance signals embedded in risk scores
- Creates a falsifiable research hypothesis (H₁) for RQ1

### Negative
- Requires a ground-truth dataset for validation (motivates E1)
- Weight parameters must be documented and justified (see docs/RISK_ENGINE.md)
- "Black box" risk to practitioners — mitigated by `risk_breakdown` in engine output

### Neutral
- All weight parameters are in `risk_engine.py` as named constants — easily auditable

---

## References

- [CVSS31] FIRST.Org. "CVSS v3.1 Specification Document." 2019.
- [Jacobs2021] Jacobs et al. "Improving Vulnerability Remediation Through Better Exploit Prediction." USENIX Security, 2021.
- [CISA-KEV] CISA. "Known Exploited Vulnerabilities Catalog." 2021–present.
- [Spring2021] Spring et al. "EPSS: Exploit Prediction Scoring System." IEEE S&P Workshop, 2021.
- [OWASP-RRM] OWASP. "Risk Rating Methodology." 2021.
- [FAIR] The Open Group. "Factor Analysis of Information Risk." 2009.
