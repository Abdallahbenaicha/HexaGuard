# SecuraX — Dataset Policy and Schema

> **Version**: 2.0.0 | **Last updated**: 2026-07-30

## Purpose

This document defines:
1. The canonical schema for all scanner outputs produced by SecuraX
2. The metadata requirements for every research dataset
3. Reproducibility instructions for all datasets
4. Dataset licensing and citation requirements

**Principle**: *Research without reproducibility is not research.*
Every dataset produced by SecuraX must be independently reproducible.

---

## 1. Scanner Output Schema

All SecuraX scanner engines produce output conforming to the following schema.
The Python dataclass definition is in `backend/scanners/schema.py`.

### 1.1 Top-level `ScanResult`

```json
{
    "scan_type":         "string",   // REQUIRED: see §1.3
    "target":            "string",   // REQUIRED: scanned target (URL, IP, path)
    "vulnerabilities":   [],         // REQUIRED: array of Vulnerability objects
    "scanner_versions":  {},         // REQUIRED: tool versions (see §1.4)
    "scan_duration_s":   0.0,        // REQUIRED: wall-clock time in seconds
    "timestamp":         "string",   // REQUIRED: ISO 8601 UTC timestamp
    "engine_version":    "string",   // REQUIRED: risk_engine.VERSION
    "error":             null,       // nullable: error message if scan failed
    "metadata":          {}          // optional: scan-type-specific metadata
}
```

### 1.2 `Vulnerability` object

```json
{
    "severity":         "string",   // REQUIRED: critical|high|medium|low|info
    "check":            "string",   // REQUIRED: machine-readable check ID
    "title":            "string",   // REQUIRED: short human-readable title
    "description":      "string",   // REQUIRED: full description
    "evidence":         "string",   // optional: proof (HTTP response, code snippet)
    "cve_ids":          [],         // optional: list of CVE identifiers
    "cwe_id":           "string",   // optional: CWE identifier (e.g., "CWE-79")
    "owasp_category":   "string",   // optional: e.g., "A03:2021-Injection"
    "mitre_attack":     "string",   // optional: e.g., "T1190"
    "cvss_score":       null,       // optional: float 0.0–10.0 from NVD
    "remediation":      "string",   // optional: actionable fix guidance
    "false_positive":   false       // optional: manually triaged false positive
}
```

### 1.3 Valid `scan_type` values

| Value | Scanner Module | Description |
|-------|---------------|-------------|
| `web` | `web_scanner.py` | Passive HTTP security header and config checks |
| `dast` | `dast_scanner.py` | Dynamic active injection testing (ZAP/Nikto/Nuclei) |
| `sast` | `sast_scanner.py` | Static source code analysis (Bandit/Semgrep/Gitleaks) |
| `network_ext` | `netscan_scanner.py` | External network/port scan (Nmap) |
| `network_int` | `netscan_scanner.py` | Internal network scan |
| `ssl` | `ssl_scanner.py` | SSL/TLS certificate and cipher analysis |
| `dependencies` | `dep_scanner.py` | Known-CVE dependency scan (OSV.dev) |
| `server_int` | `server_int.py` | White-box Apache config analysis |
| `server_ext` | `server_ext.py` | Black-box server probing |
| `docker` | `docker_scanner.py` | Dockerfile and image security review |
| `dns` | `dns_scanner.py` | DNS/email SPF/DKIM/DMARC analysis |
| `wordpress` | `wordpress_scanner.py` | WordPress-specific vulnerability detection |

### 1.4 `scanner_versions` format

Every scan result must record the versions of all tools invoked:

```json
{
    "scanner_versions": {
        "bandit": "1.8.3",
        "nmap": "7.94",
        "zap": "2.14.0",
        "nikto": "2.1.6",
        "securax_risk_engine": "3.0.0"
    }
}
```

---

## 2. Dataset Metadata Requirements

Every research dataset produced from SecuraX scans must include a
`metadata.json` file in the dataset directory:

```json
{
    "dataset_id":          "string",    // unique identifier (e.g., "d2_real_world_scans")
    "version":             "string",    // semantic version
    "created_at":          "string",    // ISO 8601
    "created_by":          "string",    // researcher name / institution
    "description":         "string",    // what was scanned and why
    "research_question":   "string",    // links to RESEARCH_ROADMAP.md section
    "environment": {
        "os":              "string",    // e.g., "Ubuntu 22.04.3 LTS"
        "python":          "string",    // e.g., "3.12.2"
        "securax_version": "string",    // git tag or commit SHA
        "risk_engine_version": "string" // risk_engine.VERSION
    },
    "scanner_versions":    {},          // same format as §1.4
    "scan_commands":       [],          // exact commands or API calls used
    "targets": {
        "count":           0,
        "description":     "string",    // what targets were scanned
        "authorisation":   "string"     // evidence of authorisation to scan
    },
    "ground_truth": {
        "method":          "string",    // how ground truth was determined
        "labelled_by":     "string",    // who labelled the data
        "label_date":      "string"
    },
    "statistics": {
        "total_scans":     0,
        "total_findings":  0,
        "severity_distribution": {}
    },
    "license":             "string",    // e.g., "CC BY 4.0"
    "citation":            "string"     // how to cite this dataset
}
```

---

## 3. Directory Structure

```
datasets/
├── d1_synthetic_benchmark/
│   ├── metadata.json
│   ├── ground_truth.json       # 50 synthetic cases with expected labels
│   └── README.md
├── d2_real_world_scans/        # (planned — see RESEARCH_ROADMAP.md E1)
│   ├── metadata.json
│   ├── scans/                  # individual scan result JSON files
│   └── ground_truth.json
├── d3_dvwa_findings/           # (planned — E2)
└── ...
```

---

## 4. Reproducibility Instructions

To reproduce any SecuraX dataset:

### Step 1 — Environment
```bash
git clone https://github.com/Abdallahbenaicha/SecuraX.git
git checkout <securax_version from metadata.json>
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Step 2 — Database
```bash
cp .env.example .env
# Set SECRET_KEY to any 32+ char string for local use
python app.py
```

### Step 3 — Run scans
Use the exact `scan_commands` from `metadata.json`.
For API-based scans:
```bash
# Example: reproduce a web scan
curl -X POST http://localhost:5000/api/scan/web \
  -H "Content-Type: application/json" \
  -d '{"url": "<target>", "mode": "full"}'
```

### Step 4 — Verify risk scores
```bash
cd backend
python -c "
from risk_engine import calculate_risk_v2, VERSION
print('Engine version:', VERSION)
# Load scan result from dataset and recompute
import json
result = json.load(open('../datasets/d2_real_world_scans/scans/scan_001.json'))
bd = calculate_risk_v2(result)
print('Reproduced risk level:', bd.risk_level)
print('Reproduced final score:', bd.final_score)
"
```

**Note on CISA KEV**: CISA KEV results are non-deterministic unless you pin
the KEV snapshot. To reproduce exactly, either:
- Mock the KEV set: `from unittest.mock import patch; patch('risk_engine._KEV_CACHE', kev_snapshot_set)`
- Or record the KEV snapshot date in `metadata.json` and use the CISA KEV archive.

---

## 5. Ground Truth Format

```json
{
    "dataset_id": "d2_real_world_scans",
    "labelled_entries": [
        {
            "scan_file": "scans/scan_001.json",
            "expected_risk_level": "high",
            "expected_severity_distribution": {
                "critical": 0, "high": 2, "medium": 5, "low": 3
            },
            "true_positives": ["xss_check_id_1", "sqli_check_id_2"],
            "false_positives": ["missing_header_check_id_3"],
            "confirmed_exploitations": [],
            "labelling_notes": "string"
        }
    ]
}
```

---

## 6. Quality Validation

Before a dataset is accepted into the repository, it must pass:

```bash
# Validate all scan results conform to the schema
python -c "
from backend.scanners.schema import validate_scan_result
import json, glob

errors = []
for f in glob.glob('datasets/**/*.json', recursive=True):
    result = json.load(open(f))
    if 'scan_type' in result:  # is a scan result
        errs = validate_scan_result(result)
        if errs:
            errors.append((f, errs))

if errors:
    for f, errs in errors:
        print(f'INVALID: {f}')
        for e in errs:
            print(f'  - {e}')
    exit(1)
else:
    print('All scan results valid.')
"
```

---

## 7. Licensing

All SecuraX datasets are released under **Creative Commons Attribution 4.0
International (CC BY 4.0)** unless stated otherwise in the dataset's
`metadata.json`.

When using a SecuraX dataset in research, cite:
1. The SecuraX platform itself (see `CITATION.cff`)
2. The specific dataset using the `citation` field from `metadata.json`

---

## 8. Data Privacy

**Before contributing a dataset**:
- Ensure you have written authorisation to scan all targets
- Remove or redact any personal data from scan results
- Verify that IP addresses and domain names may be published
- Review the target's terms of service

SecuraX maintainers reserve the right to reject datasets that do not comply
with this policy.
