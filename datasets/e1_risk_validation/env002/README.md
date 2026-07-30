# env002 — OWASP Juice Shop

| Property | Value |
|----------|-------|
| **Target** | OWASP Juice Shop (latest) |
| **URL** | http://localhost:3000 |
| **Data type** | Synthetic v1.0.0 |
| **Finding count** | 10 |
| **Experiment** | E1 (Risk Score Validation, RQ1) |

## Background

OWASP Juice Shop is a deliberately insecure web application written in Node.js/Angular
with a wide range of modern web vulnerabilities. It includes payment functionality
(PCI-DSS relevance) and user PII (GDPR relevance), making it ideal for testing
compliance-aware risk scoring.

**Source**: https://owasp.org/www-project-juice-shop/  
**License**: MIT

## Risk Distribution

```
Critical: ██ 2   (juice-001, juice-002)
High:     █████ 5 (juice-003..007)
Medium:   ██ 2   (juice-008, juice-009)
Low:      █ 1    (juice-010)
```

## Deployment

```bash
docker-compose up -d
# Access at: http://localhost:3000
```
