# env005 — PortSwigger Web Security Academy (API Security)

| Property | Value |
|----------|-------|
| **Target** | Custom vulnerable REST/GraphQL API |
| **URL** | http://localhost:8989 |
| **Data type** | Synthetic v1.0.0 |
| **Finding count** | 10 |
| **Experiment** | E1 (Risk Score Validation, RQ1) |

## Background

This environment covers **OWASP API Security Top 10 (2023)** vulnerabilities,
based on PortSwigger Web Security Academy API testing labs. With `internet_facing=True`,
`has_pii=True`, and `has_payment=True`, this is the **highest criticality** environment.

## Risk Distribution

```
Critical: ███ 3   (api-001..003: BOLA, Mass Assignment, SSRF)
High:     ████ 4  (api-004..007)
Medium:   ██ 2   (api-008..009)
Low:      █ 1    (api-010)
```

## Research Significance

This environment is the **most important for GDPR/PCI-DSS testing**:
- `has_pii=True` triggers GDPR Art. 32/33 compliance checks
- `has_payment=True` triggers PCI-DSS Req. 6.3 compliance checks
- `asset_criticality="critical"` activates the asset criticality multiplier

This directly tests RQ5 (Compliance Assessment Completeness) in addition to RQ1.

## Deployment

```bash
docker-compose up -d
# API accessible at: http://localhost:8989
```
