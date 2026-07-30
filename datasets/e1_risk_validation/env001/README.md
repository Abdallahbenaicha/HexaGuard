# env001 — DVWA (Damn Vulnerable Web Application)

## Overview

| Property | Value |
|----------|-------|
| **Target** | DVWA v1.10 |
| **URL** | http://localhost:8080/dvwa/ |
| **Data type** | Synthetic v1.0.0 |
| **Finding count** | 10 |
| **Experiment** | E1 (Risk Score Validation, RQ1) |

## Background

DVWA (Damn Vulnerable Web Application) is a PHP/MySQL web application designed
to practice common web vulnerabilities in a legal and controlled environment.
It is widely used in academic and professional security training.

**Source**: https://github.com/digininja/DVWA  
**License**: GNU GPL v3.0

## Vulnerability Coverage

This environment covers the following OWASP Top 10 (2021) categories:

| ID | Category | Findings |
|----|----------|---------|
| A01 | Broken Access Control | CSRF (dvwa-005) |
| A02 | Cryptographic Failures | Hardcoded secrets (dvwa-007) |
| A03 | Injection | SQLi (dvwa-001), XSS×2 (dvwa-002, dvwa-009), CMDi (dvwa-003) |
| A04 | Insecure Design | File upload (dvwa-010) |
| A05 | Security Misconfiguration | LFI (dvwa-004), Missing headers (dvwa-008) |
| A07 | Auth Failures | Broken CAPTCHA (dvwa-006) |

## Risk Distribution

```
Critical: ███ 3  (dvwa-001, dvwa-003, dvwa-010)
High:     ████ 4  (dvwa-002, dvwa-004, dvwa-007, dvwa-009)
Medium:   ██ 2   (dvwa-005, dvwa-006)
Low:      █ 1    (dvwa-008)
```

## Deployment

```bash
docker-compose up -d
# Access at: http://localhost:8080/dvwa/
# Setup DB: http://localhost:8080/dvwa/setup.php
```

## Running SecuraX Against This Environment

```bash
# After docker-compose up -d
python research/run_experiment.py \
  --experiment e1 \
  --environment env001 \
  --target http://localhost:8080/dvwa/
```

## Ground Truth

See [`ground_truth.json`](ground_truth.json) for all 10 labelled findings.

Each entry documents:
- Vulnerability ID, CWE, OWASP category
- Expected risk level
- Rationale for the label
- Source tier (expert_elicitation)

## Known Limitations

- v1.0.0 data is **synthetic** — real lab deployment pending.
- DVWA has a "security level" setting (Low/Medium/High/Impossible).
  All entries assume **Low** security level (worst case).
- Some DVWA vulnerabilities require manual steps not automatable by scanners.
