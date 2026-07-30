# Experiment 2 — False Positive Rate Study (E2)

> **Research Question**: RQ2 — What is the empirical false positive rate for each of the
> 11 scanner engines integrated in SecuraX?

## Status

🔴 **Not started** — Awaiting lab deployment of intentionally vulnerable applications.

## Planned Protocol

1. Deploy all 5 environments from `e1_risk_validation/` in Docker
2. Run all 11 SecuraX scanner engines against each target
3. Manually triage every finding: True Positive (TP) / False Positive (FP) / Informational
4. Compute FPR per scanner, per severity, per check type
5. Document scanner versions and environment configs in this directory

## Directory Structure (Planned)

```
e2_fpr_study/
├── README.md                    ← this file
├── triage_template.json         ← schema for manual triage records
├── dvwa/
│   ├── raw_scan_output.json     ← all 11 scanner outputs
│   ├── triage_results.json      ← manual TP/FP classifications
│   └── fpr_summary.csv
├── juiceshop/
├── webgoat/
├── metasploitable/
└── portswigger_api/
```

## Expected Output

```
results/e2_fpr_study/
  fpr_by_scanner.csv
  fpr_by_severity.csv
  fpr_by_check_type.csv
  plots/
    fpr_heatmap.png
    precision_by_scanner.png
```

## References

- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115: Technical Guide to Information Security Testing](https://doi.org/10.6028/NIST.SP.800-115)
