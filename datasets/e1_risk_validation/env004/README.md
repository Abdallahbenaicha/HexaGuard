# env004 — Metasploitable 2 (Network Infrastructure)

| Property | Value |
|----------|-------|
| **Target** | Metasploitable 2 |
| **Data type** | Synthetic v1.0.0 |
| **Finding count** | 10 |
| **Experiment** | E1 (Risk Score Validation, RQ1) |

## Background

Metasploitable 2 is a vulnerable Linux VM from Rapid7 designed for Metasploit practice.
It contains many **real CVEs with public exploits** (KEV candidates), making it ideal
for testing SecuraX's temporal adjustment (exploit_known flag + CISA KEV integration).

## Risk Distribution

```
Critical: ████ 4  (meta-001..004: all have known public exploits)
High:     ████ 4  (meta-005..008)
Medium:   ██ 2   (meta-009..010)
```

## Research Significance

This environment specifically tests the **temporal scoring component** of SecuraX:
- Findings with `exploit_known=True` should score higher than identical findings without
- The KEV integration should boost scores for CVE-2011-2523, CVE-2007-2447, CVE-2008-0166

**This is a key differentiator** between SecuraX and a naive CVSS baseline.

## Deployment

```bash
docker-compose up -d
# Network services exposed on various ports (see docker-compose.yml)
```
