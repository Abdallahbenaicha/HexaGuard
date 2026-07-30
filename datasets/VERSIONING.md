# SecuraX Dataset — Versioning Policy

> **Version**: 1.0 | **Policy adopted**: 2026-07-30

## Semantic Versioning for Datasets

SecuraX datasets follow **Semantic Versioning** adapted for research data:

```
dataset-vMAJOR.MINOR.PATCH
```

| Component | Increment when... |
|-----------|------------------|
| **MAJOR** | Breaking change: schema changes, label reassignment across existing entries |
| **MINOR** | Backward-compatible addition: new environments, new scan results added |
| **PATCH** | Backward-compatible fix: typos, metadata corrections, checksum updates |

---

## Version History

| Version | Date | Description | DOI |
|---------|------|-------------|-----|
| v1.0.0 | 2026-07-30 | Initial synthetic benchmark (50 cases, 5 environments) | *pending Zenodo* |
| v1.1.0 | *planned* | + DVWA real findings (E2) | — |
| v1.2.0 | *planned* | + JuiceShop real findings (E2) | — |
| v2.0.0 | *planned* | Real-world scans with 90-day validation (E1) | — |

---

## How to Assign a DOI via Zenodo

> [!NOTE]
> Assigning a DOI makes your dataset independently citable — a key requirement
> for any publication using this data.

### Step-by-step:

1. **Create a Zenodo account** at https://zenodo.org/ (free, CERN-hosted)
2. **Link your GitHub repository** via the Zenodo GitHub integration
3. **Create a GitHub Release** tagged as `dataset-v1.0.0`
4. **Zenodo automatically** mints a DOI for that release (e.g., `10.5281/zenodo.XXXXXXX`)
5. **Update `CITATION.cff`** and `datasets/README.md` with the new DOI
6. **Update this file** with the DOI in the version history table

### Recommended metadata for Zenodo upload:

```yaml
title: "SecuraX Vulnerability Risk Prioritization Benchmark Dataset"
description: "Multi-dimensional vulnerability risk scoring evaluation dataset"
upload_type: dataset
license: cc-by-4.0
keywords:
  - cybersecurity
  - vulnerability management
  - risk scoring
  - benchmark dataset
  - CVSS
  - penetration testing
communities:
  - cybersecurity
  - information-security
```

---

## Dataset Integrity

Every dataset version includes a manifest file (`dataset-vX.Y.Z-manifest.json`)
with SHA-256 checksums of all dataset files.

### Verifying integrity:

```bash
python research/verify_dataset.py --manifest datasets/dataset-v1.0.0-manifest.json
```

This ensures that published results are reproducible with the exact same data.

---

## Deprecation Policy

- A dataset version is **deprecated** when a MAJOR version supersedes it.
- Deprecated versions are **never deleted** — they remain archived for reproducibility.
- Papers citing a deprecated version should note the version explicitly.

---

## Contributing New Data

To contribute a new environment or scan result:

1. Create `datasets/e1_risk_validation/envNNN/` following the schema in `datasets/README.md`
2. Add a `metadata.json` with source documentation
3. Add a `ground_truth.json` with labelled findings
4. Open a PR referencing the experiment it supports (E1, E2, or E3)
5. A maintainer will review and increment the MINOR version

**Do NOT directly modify `ground_truth.json` for existing entries** without opening
an issue for discussion — label changes are a MAJOR version increment.
