# Experiment 3 — Attack Chain Detection (E3)

> **Research Question**: RQ3 — Does the rule-based attack chain detector in `risk_engine.py`
> identify realistic multi-step attack paths with acceptable precision?

## Status

🟡 **Partially implemented** — The detector exists in `risk_engine.py`; evaluation pending.

## Planned Protocol

1. Collect documented CVE exploitation chains from MITRE ATT&CK and NVD
2. Synthesise scan results matching each chain's preconditions
3. Apply `_detect_attack_chains()` to each synthetic result
4. Compute precision and recall for detected chains

## Known Attack Chains (from MITRE ATT&CK)

| Chain ID | Description | ATT&CK Techniques |
|----------|-------------|-------------------|
| AC-001 | XSS → Session Hijack → Account Takeover | T1185, T1539 |
| AC-002 | SQLi → Data Exfiltration | T1190, T1005 |
| AC-003 | RCE via File Upload → Persistence | T1190, T1059, T1543 |
| AC-004 | SMB + CMDi → Lateral Movement | T1021.002, T1059.001 |
| AC-005 | JWT Forge → Privilege Escalation | T1078, T1134 |
| AC-006 | SSRF → Cloud Metadata → Credential Theft | T1552.005, T1606 |

## Directory Structure (Planned)

```
e3_attack_chains/
├── README.md
├── known_chains.json          ← documented attack chains with ATT&CK references
├── synthetic_inputs.json      ← scan inputs designed to trigger each chain
├── detection_results.json     ← output of _detect_attack_chains()
└── evaluation_results.csv     ← precision/recall per chain
```
