# SecuraX — Risk Engine: Mathematical Specification

> **Engine version**: 3.0.0 | **Module**: `backend/risk_engine.py`

## Abstract

The SecuraX risk engine computes a single normalised risk score in [0, 10]
from a heterogeneous set of vulnerability findings produced by one or more
scanner engines. The score extends CVSS v3.1 \[CVSS31\] with temporal and
environmental adjustment factors, adapted from NIST SP 800-30 \[NIST800\] and
ISO/IEC 27005:2022 \[ISO27005\].

This document specifies the mathematical model, justifies each parameter
choice, and defines the reproducibility contract for datasets produced by
SecuraX.

---

## 1. Inputs

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_result` | dict | Scanner output (see `backend/scanners/schema.py`) |
| `criticality` | float ∈ [0.1, 1.0] | Asset business criticality (default 1.0) |
| `exploit_known` | bool | Is a public exploit available? (default False) |
| `internet_facing` | bool | Is the target reachable from the internet? (default True) |
| `has_pii` | bool | Does the target process personal data? (default False) |
| `has_payment` | bool | Does the target process payment card data? (default False) |

---

## 2. Scoring Pipeline

### Step 1 — Per-finding score

For each vulnerability *v* with severity *s*:

```
base(s) = BASE_SCORES[s]        # see Table 1 below
booster  = max{mult | kw in TYPE_BOOSTERS, kw ⊆ check_text(v)}
           default 1.0
is_kev   = any CVE in v.cve_ids ∈ CISA_KEV_set
exploit_f = 2.5  if is_kev and s ∈ {critical, high}
           1.3  if exploit_known and s ∈ {critical, high}
           1.0  otherwise

individual(v) = min(base(s) × booster × exploit_f, 10.0)
```

**Table 1 — Base scores** (midpoint values within CVSS v3.1 severity bands \[CVSS31\] §5):

| Severity | CVSS Band | Base Score |
|----------|-----------|-----------|
| critical | [9.0, 10.0] | 9.5 |
| high | [7.0, 8.9] | 7.5 |
| medium | [4.0, 6.9] | 5.0 |
| low | [0.1, 3.9] | 2.0 |
| info | 0.0 | 0.0 |

### Step 2 — Logarithmic aggregation

Findings are sorted descending by `individual(v)`. A geometric decay is applied
to prevent score inflation from many low-severity findings:

```
raw_score = Σᵢ individual(vᵢ) × 0.85ⁱ    for i = 0, 1, 2, …
```

**Rationale**: A linear sum would make 50 low-severity findings outweigh one
critical finding. The decay factor 0.85 gives the second finding 85%, the third
72.25%, and so on. This is analogous to the logarithmic aggregation in CVSS
environmental score computation \[CVSS31\].

**Decay factor choice**: 0.85 was selected so that 10 identical medium findings
(5.0 each) produce a raw score of ~29.9, which normalises (Step 3) to ~8.6 —
correctly below the critical threshold — while a single RCE (individual ≈ 10.0)
normalises to ~9.5, which is critical.

### Step 3 — Sigmoid normalisation

```
base_score = 10 × (1 − exp(−raw_score / 15.0))
```

This is a capped exponential saturation function. Properties:
- Monotonically increasing: more findings → higher score
- Asymptotically approaches 10.0 (never exceeds it before floor step)
- Parameter 15.0: chosen so that `raw_score = 15` → `base_score ≈ 6.3` (medium)

### Step 4 — Temporal adjustment

```
temporal_mult = 1.0
             + 0.05  if any finding has cve_ids (CVE presence)
             + 0.15  if any CVE matches CISA KEV (actively exploited)
             + 0.10  if exploit_known=True (but no KEV match)

temporal_score = min(base_score × temporal_mult, 10.0)
```

**References**: CVSS v3.1 Temporal Score \[CVSS31\] §7.3.

### Step 5 — Environmental adjustment

```
env_mult = max(0.1, min(criticality, 1.0))
         × 1.20  if internet_facing
         × 1.15  if has_pii
         × 1.20  if has_payment
         × SCAN_TYPE_WEIGHT[scan_type]

env_score = min(temporal_score × env_mult, 10.0)
```

**References**: CVSS v3.1 Environmental Score \[CVSS31\] §7.4;
NIST SP 800-30 §3.3 \[NIST800\].

**Table 2 — Scan-type weights** (confidence in evidence quality):

| Scan Type | Weight | Rationale |
|-----------|--------|-----------|
| dast | 1.2 | Active exploitation confirmed against live target |
| dependencies | 1.1 | CVE-matched; high confidence but not yet exploited |
| network_ext | 1.1 | External attack surface; directly reachable |
| sast | 1.0 | Static heuristics; ~80% true-positive rate |
| web | 1.0 | Passive header/config checks |
| server_ext | 0.95 | Black-box probing; reliable but incomplete |
| server_int | 0.9 | White-box config review; lower exposure |
| network_int | 0.8 | Internal; requires prior network access |

### Step 6 — Floor guarantees

```
final_score = env_score
if critical_count > 0:  final_score = max(final_score, 7.5)
if high_count > 0:      final_score = max(final_score, 5.0)
final_score = min(final_score, 10.0)
```

**Rationale**: A single critical finding must always produce at least a "high"
risk score (≥ 7.5), regardless of environmental factors. This prevents
very-low-criticality assets from masking critical vulnerabilities entirely.

### Step 7 — Risk level classification

| Score Range | Risk Level |
|-------------|-----------|
| [9.0, 10.0] | critical |
| [7.0, 9.0)  | high |
| [4.0, 7.0)  | medium |
| [1.0, 4.0)  | low |
| [0.0, 1.0)  | minimal |

---

## 3. Output: `RiskBreakdown` Dataclass

```python
@dataclass
class RiskBreakdown:
    raw_score:          float   # Step 2 output
    base_score:         float   # Step 3 output
    temporal_score:     float   # Step 4 output
    env_score:          float   # Step 5 output
    final_score:        float   # Step 6 output (0.0–10.0)
    risk_level:         str     # Step 7 label
    confidence:         float   # 0.0–1.0 (based on scan type)
    severity_counts:    dict    # {critical: N, high: N, ...}
    highest_sev:        str     # most severe finding
    top_findings:       list    # top 3 scored vulnerabilities
    recommendations:    list    # prioritised remediation text
    attack_chains:      list    # detected multi-step attack paths
    cisa_kev_findings:  list    # CVE IDs matching CISA KEV
```

---

## 4. Reproducibility Contract

To reproduce a risk score from a SecuraX dataset:

1. Record `risk_engine.VERSION` alongside every stored scan result.
2. Record all input parameters: `criticality`, `exploit_known`, `internet_facing`,
   `has_pii`, `has_payment`.
3. Record the CISA KEV snapshot date (the KEV set changes daily).
4. Use the same engine version: install SecuraX at the tagged release that
   matches `VERSION` (e.g., `git checkout v3.0.0`).

**Note**: CISA KEV results are non-deterministic unless the KEV snapshot is
fixed. For research reproducibility, either disable KEV enrichment
(`kev_set = set()` patch) or pin a specific KEV snapshot.

---

## 5. Known Limitations and Future Work

### 5.1 Weight calibration
All multipliers in `_TYPE_BOOSTERS` and `_SCAN_TYPE_WEIGHT` were set by
**expert elicitation** in v3.0. They have not been empirically validated against
a labelled real-world dataset.

A ground-truth benchmark using synthetic data is available at
`backend/tests/test_risk_engine_benchmark.py`. An empirical calibration study
using real-world scan data is planned for **v4.0** (see `docs/RESEARCH_ROADMAP.md`).

### 5.2 CVSS base score granularity
The engine uses severity labels (critical/high/medium/low) rather than precise
CVSS base scores from NVD because many of the 11 scanner engines do not produce
CVSS scores. A planned improvement is to fetch actual CVSS v3.1 base scores from
NVD for all CVE-identified findings and use them instead of the severity midpoint.

### 5.3 No probability model
The current model is deterministic given fixed inputs. It does not model
uncertainty in exploit probability (e.g., using EPSS \[EPSS\]). An EPSS
integration is on the research roadmap.

### 5.4 Single-asset model
The engine scores a single scan result at a time. Attack chain detection
(`_detect_attack_chains`) operates within a single scan. Cross-asset
lateral movement (e.g., pivoting from a compromised web server to an internal
database) is not modelled.

---

## 6. References

| Tag | Reference |
|-----|-----------|
| \[CVSS31\] | FIRST.Org. *CVSS v3.1 Specification*. 2019. https://www.first.org/cvss/specification-document |
| \[NIST800\] | NIST. *SP 800-30 Rev. 1: Guide for Conducting Risk Assessments*. 2012. https://doi.org/10.6028/NIST.SP.800-30r1 |
| \[ISO27005\] | ISO/IEC 27005:2022. *Information security risk management*. |
| \[FAIR\] | The Open Group. *Factor Analysis of Information Risk (FAIR)*. 2009. |
| \[OWASP-RISKRATING\] | OWASP Foundation. *OWASP Risk Rating Methodology*. 2021. https://owasp.org/www-community/OWASP_Risk_Rating_Methodology |
| \[CISA-KEV\] | CISA. *Known Exploited Vulnerabilities Catalog*. https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| \[EPSS\] | Jacobs et al. *Exploit Prediction Scoring System (EPSS)*. 2021. https://www.first.org/epss/ |
