# Experiment 1 — Risk Score Validation (E1)

> **Research Question**: RQ1 — Is the multi-dimensional SecuraX risk score a better
> predictor of actual vulnerability impact than a naive CVSS-only severity lookup?

## Overview

This directory contains the benchmark dataset for Experiment 1 (E1), which evaluates
the SecuraX multi-dimensional risk engine against four baselines on labelled scan results.

## Environments

| Environment | Target | Scanner Focus | Status |
|-------------|--------|---------------|--------|
| [env001](env001/) | DVWA | Web scanner, DAST | ✅ Synthetic v1.0 |
| [env002](env002/) | OWASP Juice Shop | Web scanner, API | ✅ Synthetic v1.0 |
| [env003](env003/) | WebGoat | Authentication, SAST | ✅ Synthetic v1.0 |
| [env004](env004/) | Metasploitable 2 | Network, SSL | ✅ Synthetic v1.0 |
| [env005](env005/) | PortSwigger Labs | DAST, API vulns | ✅ Synthetic v1.0 |

## Running the Experiment

```bash
# Run full E1 experiment
python research/run_experiment.py --experiment e1 --output results/

# Run with specific baselines
python research/run_experiment.py --experiment e1 --baselines cvss rule random priority
```

## Expected Outputs

```
results/e1_risk_validation/
  precision.csv
  recall.csv
  f1_scores.csv
  confusion_matrix.csv
  plots/
    precision_recall_curve.png
    roc_curve.png
    ablation_study.png
  paper_tables/
    table1_comparison.tex
    table2_per_class.tex
```

## Data Provenance

All v1.0.0 data is **synthetic** — constructed by a domain expert to represent
realistic vulnerability scenarios from well-known intentionally vulnerable applications.

Real deployments of these applications will be used for v1.1.0+ validation.
