# SecuraX — Datasets

> **Dataset Version**: v1.0.0 | **Last updated**: 2026-07-30

## Overview

This directory contains all **research datasets** used to evaluate the SecuraX
risk scoring engine. All datasets follow the versioning and documentation
policy defined in [`VERSIONING.md`](VERSIONING.md).

---

## Dataset Philosophy

> **Transparency is non-negotiable.**

Every dataset entry must document:
1. **Source** — where did this case come from? (Synthetic, DVWA, CVE-NNNN, etc.)
2. **Ground Truth** — who assigned the label and by what criteria?
3. **Rationale** — why is this the correct label?

A dataset without provenance is scientifically worthless.

---

## Directory Structure

```
datasets/
│
├── README.md                        ← this file
├── VERSIONING.md                    ← version policy + DOI instructions
├── CHANGELOG.md                     ← dataset change history
├── VERSION                          ← current version string
├── dataset-v1.0.0-manifest.json     ← SHA-256 checksums of all files
│
├── e1_risk_validation/              ← Experiment 1: Risk Score Validation (RQ1)
│   ├── README.md
│   ├── env001/                      ← DVWA environment
│   ├── env002/                      ← OWASP Juice Shop
│   ├── env003/                      ← WebGoat
│   ├── env004/                      ← Metasploitable network
│   └── env005/                      ← PortSwigger Labs (API vulns)
│
├── e2_fpr_study/                    ← Experiment 2: False Positive Rate Study (RQ2)
│   ├── README.md
│   └── [to be populated after lab deployment]
│
└── e3_attack_chains/                ← Experiment 3: Attack Chain Detection (RQ3)
    ├── README.md
    └── [to be populated after CVE chain collection]
```

---

## Environment Schema

Each `envNNN/` directory **must** contain these files:

| File | Required | Description |
|------|----------|-------------|
| `README.md` | ✅ | Environment description, setup, and known results |
| `metadata.json` | ✅ | Version, date, scanner_versions, data_source |
| `ground_truth.json` | ✅ | Expert-labelled ground truth for each asset |
| `docker-compose.yml` | ✅ | Reproducible deployment of the vulnerable environment |
| `scan_results/securax_output.json` | ✅ | SecuraX multi-dimensional engine output |
| `scan_results/cvss_baseline.json` | ✅ | Naive CVSS-only baseline output |
| `scan_results/rule_baseline.json` | ✅ | Rule-based baseline output |

---

## Ground Truth Policy

Ground truth labels are assigned using this priority order:

1. **Confirmed exploitation** (CVE with known public exploit in CISA KEV)
2. **NVD CVSS score** + expert adjustment for environmental context
3. **Expert elicitation** — a domain expert assigns a label with written rationale
4. **Synthetic construction** — test case designed to exercise a specific code path

Every ground truth entry **must** declare which tier it uses.

---

## Data Sources

| Source | Type | Use in SecuraX |
|--------|------|----------------|
| [DVWA](https://github.com/digininja/DVWA) | Intentionally vulnerable web app | E2 FPR study |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | Intentionally vulnerable Node app | E2 FPR study |
| [WebGoat](https://github.com/WebGoat/WebGoat) | OWASP educational app | E2 FPR study |
| [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/) | Vulnerable Linux VM | E2 network study |
| [PortSwigger Web Academy](https://portswigger.net/web-security) | Web security labs | E1 API vulns |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Real-world exploit data | Risk engine calibration |
| [NVD/NIST](https://nvd.nist.gov/) | CVE database | Ground truth reference |
| Synthetic (expert-designed) | Constructed test cases | Benchmark baseline |

---

## Reproducing Results

```bash
# Install dependencies
pip install -r research/requirements-research.txt

# Run the full experiment pipeline
python research/run_experiment.py --experiment e1 --output results/

# View generated results
ls results/e1_risk_validation/
```

---

## Dataset Versioning

See [`VERSIONING.md`](VERSIONING.md) for the full versioning policy.

Quick reference:
- Current version: **v1.0.0** (synthetic benchmark only)
- Next planned: **v1.1.0** (DVWA + JuiceShop real findings)
- Long-term: **v2.0.0** (real-world scans with 90-day validation)

---

## Citation

If you use this dataset in your research, cite:

```bibtex
@dataset{securax_benchmark_v1,
  author    = {Benaicha, Abdallah},
  title     = {SecuraX Vulnerability Risk Prioritization Benchmark Dataset v1.0.0},
  year      = {2026},
  publisher = {GitHub},
  url       = {https://github.com/Abdallahbenaicha/HexaGuard},
  note      = {Synthetic benchmark dataset for multi-dimensional risk scoring evaluation}
}
```

---

## License

All datasets are released under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

You are free to share and adapt the data provided you give appropriate credit.
