# SecuraX: A Multi-Dimensional Vulnerability Risk Prioritization Platform

## Research Proposal — Conference / Master Thesis

**Author**: Abdallah Benaicha  
**Field**: Computer Science & Cybersecurity Research  
**Contact**: Abdallahbenaichatech@gmail.com  
**Date**: August 2026  
**Version**: 1.1.0 (Post-E2 Benchmark)

---

## 1. Problem Statement

Vulnerability scanners generate hundreds of findings per scan session. Security teams
with limited resources cannot remediate all findings simultaneously — they must
**prioritise**. The dominant prioritisation signal is the **CVSS score**, which maps
vulnerability severity to a number between 0 and 10.

However, CVSS has a well-documented limitation: it measures the **intrinsic severity**
of a vulnerability in isolation, not the **actual risk to a specific organisation**.

Two identical SQL injection findings with CVSS 9.8 pose different risks depending on:
- Is the affected system internet-facing or internal?
- Does it process personally identifiable information (PII)?
- Does it process payment card data?
- Is there a known public exploit (CISA KEV)?
- What is the asset's business criticality?

**Research Question (RQ1)**:
> *Is a multi-dimensional risk score — combining CVSS severity with temporal factors
> (exploit availability, CISA KEV) and environmental context (internet exposure,
> PII, compliance requirements) — a significantly better predictor of actual
> vulnerability impact than a naive CVSS-only severity lookup?*

---

## 2. Proposed Solution: SecuraX

SecuraX is a **multi-dimensional vulnerability risk prioritization platform** that:

1. **Scans** targets using 11 integrated scanner engines (web, DAST, SAST, network,
   SSL, dependency, Docker, DNS, WordPress)
2. **Scores** every finding using a multi-dimensional risk engine:
   ```
   Risk Score = f(CVSS_severity, exploitability, exposure, business_context, asset_criticality)
   ```
3. **Explains** the risk via ARIA, an AI agent (Google Gemini 2.x) that generates
   remediation guidance mapped to GDPR/PCI-DSS/ISO 27001 compliance requirements
4. **Measures** itself via a research benchmark that compares the engine against
   four baselines on a ground-truth dataset

### 2.1 Risk Scoring Pipeline

```
Input:  Scan findings + environmental context
         ↓
[1] Base Score      CVSS severity → {0.0, 2.0, 5.0, 7.5, 9.5}
         ↓
[2] Exploitability  × 1.4 if exploit_known | × 1.3 if KEV match | × 1.1 if CVE present
         ↓
[3] Exposure        × 1.25 if internet_facing
         ↓
[4] Context         + GDPR bonus if has_pii | + PCI-DSS bonus if has_payment
         ↓
[5] Asset Weight    × {1.3, 1.2, 1.0, 0.85} for {critical, high, med, low}
         ↓
[6] Attack Chains   + 0.5 per detected chain (XSS+no-CSP, SQLi, RCE+internet...)
         ↓
Output: Final score → Risk Level {minimal, low, medium, high, critical}
```

### 2.2 Baselines for Comparison

| Baseline | Description |
|----------|-------------|
| **Baseline-CVSS** | Naive severity lookup (lower bound) |
| **Baseline-Rule** | Fixed heuristics (internet_facing + counts) |
| **Baseline-Priority** | CVSS + asset criticality (no temporal) |
| **Baseline-Random** | Uniform random (statistical floor) |

---

## 3. Research Contribution

### 3.1 Primary Contribution
An empirical validation that **multi-dimensional contextual scoring** outperforms
naive CVSS-only prioritisation (macro-F1 improvement across 5 risk tiers).

### 3.2 Secondary Contributions
1. **SecuraX Benchmark Dataset v1.0.0**: A reproducible, versioned, open-source
   dataset of labelled vulnerability findings across 5 intentionally vulnerable
   environments (DVWA, Juice Shop, WebGoat, Metasploitable, PortSwigger API labs).
2. **Scanner Plugin SDK**: An extensible architecture for integrating new vulnerability
   scanner engines using a standardised interface.
3. **AI-Guided Remediation**: ARIA maps risk engine output to actionable remediation
   guidance with compliance citations.

---

## 4. Methodology

### 4.1 Experiment 1 (RQ1) — Risk Score Validation

**Dataset**: 50 synthetic findings across 5 environments (v1.0.0); planned expansion
to real-world data in v2.0.0.

**Protocol**:
1. Run SecuraX engine on all 50 findings
2. Run all 4 baselines on the same findings
3. Compare predictions to expert-elicited ground truth
4. Compute per-class precision, recall, F1 and macro-F1 (Sokolova & Lapalme, 2009)

**Hypothesis**:
- H₀: Engine macro-F1 ≤ Baseline-CVSS macro-F1
- H₁: Engine macro-F1 > Baseline-CVSS macro-F1

**Reproducibility**:
```bash
python research/run_experiment.py --experiment e1 --seed 42
```

### 4.2 Experiment 2 (RQ2) — False Positive Rate Study
_(Planned for v1.1.0)_

### 4.3 Ablation Study
Systematically disable each engine component and measure F1 drop:
```bash
python research/ablation_study.py --experiment e1
```

---

## 5. Research Questions

| ID | Question | Experiment | Status |
|----|----------|-----------|--------|
| RQ1 | Multi-dimensional > CVSS-only? | E1 | 🟡 In progress |
| RQ2 | FPR per scanner engine? | E2 | 🔴 Planned |
| RQ3 | Attack chain detection precision? | E3 | 🟡 Partial |
| RQ4 | ARIA reduces time-to-fix? | E4 | 🔴 IRB required |
| RQ5 | Compliance mapping completeness? | E5 | 🟡 In progress |

---

## 6. Evaluation Metrics

All experiments use:
- **Precision** (per class and macro-averaged)
- **Recall** (per class and macro-averaged)
- **F1-Score** (per class and macro-averaged)
- **Confusion Matrix** (5×5 multi-class)

The **macro-F1** is the primary metric because the dataset has class imbalance
(fewer critical findings than medium), and macro averaging weights all classes equally.

---

## 7. Limitations and Future Work

1. **External validity**: v1.0.0 uses synthetic data. Generalisation to real-world
   scan data requires the v2.0.0 real-world dataset (planned).
2. **Weight calibration**: Engine weights were set by expert elicitation, not learned
   from data. A data-driven approach (logistic regression or gradient boosting) is
   a natural extension.
3. **Temporal validity**: The CISA KEV catalog evolves daily. Benchmark results
   depend on the KEV state at scan time.

---

## 8. References

See `papers/references.bib` for the complete bibliography.

Key references:
- CVSS v3.1 Specification (FIRST.Org, 2019)
- Jacobs et al., "Improving Vulnerability Remediation..." (WEIS 2019)
- CISA KEV Catalog (cisa.gov/kev)
- Sokolova & Lapalme, "A Systematic Analysis of Performance Measures..." (IPM 2009)
- OWASP Risk Rating Methodology (2021)
- NIST SP 800-30 Rev. 1 (2012)
