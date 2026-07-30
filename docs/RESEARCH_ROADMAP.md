# SecuraX — Research Roadmap

> **Version**: 2.0.0 | **Last updated**: 2026-07-30

## Purpose

This document defines the **open research questions** that SecuraX is designed
to answer, the **experiments** that will answer them, and the **publication
targets** for each research contribution.

Every feature in SecuraX must connect to at least one question in this document.
If it does not, it should not be built.

---

## Open Research Questions

### RQ1 — Risk Score Calibration
> *Is the multi-dimensional SecuraX risk score a better predictor of actual
> vulnerability impact than a naive CVSS-only severity lookup?*

**Hypothesis**: Adding temporal factors (KEV, known-exploit) and environmental
context (internet-facing, PII, criticality) measurably improves classification
accuracy compared to a naive baseline.

**Measurement**: Precision, recall, and F1-score per risk tier on a labelled
dataset of real-world vulnerability scan results (ground truth = confirmed
exploitation within 90 days or CVE severity as assessed by NVD).

**Current status**: A synthetic benchmark exists (`tests/test_risk_engine_benchmark.py`).
A real-world dataset is needed for external validation.

**Planned experiment**: E1 (see below).

---

### RQ2 — False Positive Rate by Scanner Type
> *What is the empirical false positive rate for each of the 11 scanner engines
> integrated in SecuraX?*

**Hypothesis**: DAST scanners (active exploitation) have lower false positive
rates than SAST (static heuristics) and passive web scanners.

**Measurement**: Manual triage of findings on a set of intentionally vulnerable
applications (DVWA, JuiceShop, WebGoat, Metasploitable).

**Planned experiment**: E2.

---

### RQ3 — Attack Chain Detection Accuracy
> *Does the rule-based attack chain detector in `risk_engine.py` identify
> realistic multi-step attack paths with acceptable precision?*

**Hypothesis**: The keyword-matching approach detects the most common attack
chains (XSS+missing-CSP, SQLi, RCE+internet) with >80% precision on a
labelled dataset.

**Measurement**: Apply the detector to findings from known CVE exploitation
scenarios; compare detected chains to documented attack paths.

**Planned experiment**: E3.

---

### RQ4 — Remediation Guidance Quality
> *Does the ARIA-generated remediation guidance reduce time-to-fix compared
> to reading raw scanner output?*

**Hypothesis**: ARIA-generated copy-pasteable remediation code reduces
developer time-to-fix by >30% compared to raw scanner output + manual research.

**Measurement**: User study with two groups of developers fixing DVWA
vulnerabilities — one with raw scan output, one with ARIA guidance.

**Planned experiment**: E4 (requires IRB approval for human subjects study).

---

### RQ5 — Compliance Assessment Completeness
> *How completely does SecuraX map vulnerability findings to GDPR Art. 32/33,
> PCI-DSS Req. 6.3, and ISO 27001 A.14.2 requirements?*

**Hypothesis**: The current ARIA compliance mapping covers >70% of the
control requirements that are directly testable through automated scanning.

**Measurement**: Map each compliance control to a set of scanner checks;
compute coverage ratio.

**Planned experiment**: E5.

---

## Planned Experiments

### E1 — Risk Score Validation (answers RQ1)

**Status**: 🔴 Not started  
**Blocker**: Real-world labelled dataset

**Protocol**:
1. Run SecuraX against 100+ real-world targets (with authorisation)
2. Wait 90 days; record confirmed exploitations / CVE updates
3. Compare SecuraX risk level to: (a) naive CVSS baseline, (b) EPSS score
4. Compute F1 per risk tier; report macro-F1
5. Run `tests/test_risk_engine_benchmark.py` on real dataset
6. Document results in `datasets/e1_risk_validation/`

**Expected output**: A paper section with precision/recall tables comparing
three scoring approaches.

---

### E2 — False Positive Study (answers RQ2)

**Status**: 🔴 Not started  
**Blocker**: Intentionally vulnerable lab environment

**Protocol**:
1. Deploy DVWA, JuiceShop, WebGoat, Metasploitable in Docker
2. Run all 11 SecuraX scanner engines against each target
3. Manually triage every finding: True Positive / False Positive / Informational
4. Compute FPR per scanner, per severity, per check type
5. Document environment and scanner versions in `datasets/e2_fpr_study/`

**Expected output**: A FPR table per scanner engine; recommendations for
threshold tuning.

---

### E3 — Attack Chain Detection (answers RQ3)

**Status**: 🟡 Partially implemented (detector exists, no evaluation)

**Protocol**:
1. Collect documented CVE exploitation chains from MITRE ATT&CK and NVD
2. Synthesise scan results that match each chain's preconditions
3. Apply `_detect_attack_chains()` to each synthetic result
4. Compute precision (detected chains that are real) and recall (real chains detected)
5. Document in `datasets/e3_attack_chains/`

---

### E4 — Remediation UX Study (answers RQ4)

**Status**: 🔴 Not started  
**Blocker**: IRB approval, participant recruitment

---

### E5 — Compliance Coverage Mapping (answers RQ5)

**Status**: 🟡 Partially implemented (ARIA produces compliance text)

**Protocol**:
1. Extract all controls from GDPR Art. 32/33, PCI-DSS Req. 6.3, ISO 27001 A.14.2
2. Map each control to zero or more scanner checks that could evidence it
3. Compute coverage ratio = controls_with_scanner_evidence / total_controls
4. Document gaps as future scanner requirements

---

## Dataset Infrastructure

All experimental datasets must follow the policy in `docs/DATASETS.md`.

**Planned datasets**:

| Dataset ID | Experiment | Status |
|------------|-----------|--------|
| `d1_synthetic_benchmark` | E1 (baseline) | ✅ Created (`tests/test_risk_engine_benchmark.py`) |
| `d2_real_world_scans` | E1 (validation) | 🔴 Not started |
| `d3_dvwa_findings` | E2 | 🔴 Not started |
| `d4_juiceshop_findings` | E2 | 🔴 Not started |
| `d5_attack_chains` | E3 | 🔴 Not started |

---

## Publication Targets

| Research Question | Target Venue | Status |
|-------------------|-------------|--------|
| RQ1 + RQ2 | IEEE Transactions on Dependable and Secure Computing (TDSC) | 🔴 Not ready |
| RQ1 | ACM CCS Poster / NDSS Bar Track | 🔴 Not ready |
| RQ3 | ACM SIGSAC Workshop on Automated Decision Making for Active Cyber Defense | 🔴 Not ready |
| RQ5 | IEEE Security & Privacy Workshops | 🟡 In progress |
| Platform paper | USENIX Security / IEEE S&P (tools track) | 🟡 In progress |

---

## Publication Readiness Checklist

Before submitting any paper using SecuraX:

- [ ] Cite `CITATION.cff` — use the DOI if available (Zenodo)
- [ ] Record `risk_engine.VERSION` in all datasets
- [ ] Record scanner versions (from `scanner_versions` in scan output)
- [ ] Provide Docker environment for reproduction
- [ ] Include `datasets/` directory with metadata and ground truth
- [ ] Run `tests/test_risk_engine_benchmark.py` and include results
- [ ] Review `docs/RISK_ENGINE.md` — all claims must match the implementation

---

## Contributing to Research

If you are using SecuraX for your own research, please:

1. Open a GitHub Discussion describing your research question
2. Submit your experimental dataset to `datasets/` via PR (see `docs/DATASETS.md`)
3. Add your experiment to this document under "Planned Experiments"
4. Cite SecuraX using `CITATION.cff`

We actively support external research collaborations. Contact:
`innovation.team.dz@gmail.com`
