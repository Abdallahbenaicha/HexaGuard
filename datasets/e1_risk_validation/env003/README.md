# env003 — WebGoat (Java/Spring, Internal Deployment)

| Property | Value |
|----------|-------|
| **Target** | WebGoat 2023.8 |
| **URL** | http://localhost:8888/WebGoat |
| **Data type** | Synthetic v1.0.0 |
| **Finding count** | 10 |
| **Experiment** | E1 (Risk Score Validation, RQ1) |

## Background

WebGoat is an OWASP Java EE application covering modern Java security pitfalls
including JWT attacks, deserialization, and ORM injection. It is deployed as
an **internal** system (not internet-facing), allowing testing of the environmental
context adjustment in SecuraX's risk engine.

**Source**: https://github.com/WebGoat/WebGoat  
**License**: GNU GPL v2.0

## Risk Distribution

```
Critical: █ 1    (wg-001: deserialization + CVE)
High:     █████ 5 (wg-002..006)
Medium:   ███ 3   (wg-007..009)
Low:      █ 1    (wg-010)
```

## Research Significance

This environment tests whether the risk engine correctly **reduces** risk scores for
findings on internal systems compared to internet-facing ones. The SecuraX engine
applies an `internet_facing` multiplier — env003 validates that internal findings
are scored appropriately lower than identical findings in env001/env002.

## Deployment

```bash
docker-compose up -d
# Access at: http://localhost:8888/WebGoat
# Register a user at: http://localhost:8888/WebGoat/registration
```
