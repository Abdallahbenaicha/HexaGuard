# ADR-005 — Dataset Strategy: Synthetic-First

**Status**: Accepted  
**Date**: 2026-07-01  
**Deciders**: Abdallah Benaicha  
**Supersedes**: N/A  
**Related**: [datasets/README.md](../../datasets/README.md), [docs/DATASETS.md](../DATASETS.md)

---

## Context

To validate the SecuraX risk engine (RQ1), we need a labelled dataset of vulnerability
findings with ground truth risk levels.

Three dataset strategies were considered:

### Option A: Real-World-First
Collect authorised scan results from real production systems, manually triage every
finding, and use the confirmed exploitations as ground truth.

**Pros**: Maximum external validity; publishable as a real-world benchmark.  
**Cons**:
- Requires written authorisation from target system owners
- 90-day follow-up period needed for exploitation confirmation
- Ethical review may be required (Algeria: no formal IRB process, but risk exists)
- Cannot be released publicly (privacy / legal constraints on scan data)
- Timeline: 6–12 months minimum

### Option B: Existing Public Dataset
Use an existing public vulnerability dataset (e.g. NVD, CIRCL CVE Search, EPSS).

**Pros**: Immediately available; no collection needed.  
**Cons**:
- No existing dataset matches SecuraX's multi-dimensional input format
- NVD/EPSS data lacks environmental context (internet_facing, has_pii, etc.)
- Cannot demonstrate SecuraX's contextual scoring advantage

### Option C: Synthetic-First (with documented provenance)
Design test cases that exercise specific code paths, label them using expert
elicitation against documented criteria, and be completely transparent about
the synthetic origin.

**Pros**:
- Immediately actionable — can start research today
- Full control over class balance and corner case coverage
- Each entry has documented rationale → defensible ground truth
- Creates a reusable benchmark schema for future real-world data

**Cons**:
- External validity limited (synthetic ≠ real world)
- Reviewers may question generalisability

---

## Decision

**Synthetic-First with transparent documentation (Option C), planning Real-World validation for v2.0.**

This is a principled, well-established research methodology:
- Unit testing uses synthetic inputs (by definition)
- Many published security benchmarks (e.g. SARD, OWASP WebGoat test cases) are synthetic
- The key requirement is **transparency**: every entry documents its provenance tier

Ground truth tiers (in decreasing reliability):
1. Confirmed exploitation (CISA KEV / CVE with known exploit)
2. NVD CVSS + expert environmental adjustment
3. Expert elicitation with written rationale ← primary tier for v1.0.0
4. Synthetic construction (designed to exercise a code path)

The benchmark explicitly states in its docstring:
> **WARNING**: This is a synthetic dataset. Results on real-world scan data may differ.
> A real-world evaluation is planned for v4.0 (see docs/RESEARCH_ROADMAP.md).

---

## Consequences

### Positive
- Research can begin immediately with a defensible methodology
- Reproducible: dataset is versioned and checksummed
- Schema is defined — real-world data can be added to the same format

### Negative
- Claims of external validity are limited until v2.0 (real-world dataset)
- Reviewers at top venues (USENIX Security, IEEE S&P) will require real-world validation

### Neutral
- This is identical to the methodology used by the CVSS specification itself,
  which used expert elicitation to define its severity thresholds

---

## References

- [SARD] NIST. "Software Assurance Reference Dataset." https://samate.nist.gov/SARD/
- [Croft2023] Croft et al. "Data Quality for Software Vulnerability Datasets." ICSE 2023.
- [EPSS] FIRST.Org. "Exploit Prediction Scoring System." https://www.first.org/epss/
- [datasets/VERSIONING.md](../../datasets/VERSIONING.md)
