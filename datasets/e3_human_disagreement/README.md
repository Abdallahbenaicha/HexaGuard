# Experiment E3 — Human vs Automated Scanner Disagreement Benchmark

> **Dataset identifier**: `datasets/e3_human_disagreement/`
> **Version**: 1.0.0
> **License**: CC-BY-4.0

## Overview

This dataset captures empirical discrepancies between automated security scanner outputs and human expert evaluation during the **Shadow Manual Pass** and vulnerability triage within SecuraX / HexaGuard.

### Tracked Categories:
1. **False Positive (`false_positive`)**: Findings emitted by one of the 11 scanning engines that a human analyst confirmed to be non-exploitable or safe upon manual inspection.
2. **Missed by Scanner (`missed_by_scanner`)**: Vulnerabilities discovered through manual penetration testing or manual code review that automated engines completely failed to detect.
3. **Severity Dispute (`severity_dispute`)**: Cases where the automated heuristic CVSS score was found by human analysts to overestimate or underestimate actual business/operational risk.

## Schema

Each entry in `ground_truth.json` contains:

```json
{
  "id": "e3-1725840000000-abcd",
  "timestamp": "2026-09-09T03:00:00Z",
  "report_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target": "example.com",
  "vuln_type": "xss",
  "scanner_id": "dast_zap",
  "disagreement_type": "false_positive",
  "rationale": "Input parameter is strictly sanitized by htmlspecialchars() before reflection",
  "evidence": "Observed rendered response is safe HTML entity encoded",
  "user_id": 1
}
```

## Research Applications

- Benchmarking scanner precision and recall against real-world human ground truth.
- Calibrating machine-learning triage models and automated suppression rules.
- Reproducible evaluation of human-in-the-loop security verification.
