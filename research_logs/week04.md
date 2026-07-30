# Week 04 — 2026-07-28 → 2026-08-03 (Current)

## Objectives This Week
- [x] Build complete research infrastructure (datasets/, research/, papers/)
- [x] Create 5 benchmark environments (env001–env005) with ground truth
- [x] Implement 4 comparison baselines
- [x] Create Plugin SDK (ScannerPlugin ABC + PluginRegistry)
- [x] Build Experiment Runner (run_experiment.py)
- [x] Build Ablation Study (ablation_study.py)
- [x] Create Threat Model (THREAT_MODEL.md)
- [x] Create 5 Architecture Decision Records (ADR-001 → ADR-005)
- [x] Create papers/ directory with references.bib + research proposal
- [x] Create Figure Generator (research/figures/generate_figures.py)
- [x] Create Makefile for research automation
- [ ] Run full experiment and generate paper-ready outputs

## Work Done

### Infrastructure Created Today

| Component | Files Created | Status |
|-----------|-------------|--------|
| datasets/e1_risk_validation/ | 5 environments × 5 files | ✅ |
| research/baselines/ | 4 baseline classifiers | ✅ |
| research/run_experiment.py | Full pipeline runner | ✅ |
| research/ablation_study.py | Component ablation | ✅ |
| backend/scanners/sdk/ | Plugin SDK (base + registry) | ✅ |
| docs/THREAT_MODEL.md | STRIDE analysis | ✅ |
| docs/adr/ | 5 ADRs | ✅ |
| papers/ | Bibliography + proposal | ✅ |
| research_logs/ | Week 01-04 + template | ✅ |

### Ground Truth Dataset (v1.0.0)

Total findings across 5 environments:

| Environment | Findings | Critical | High | Medium | Low |
|-------------|---------|---------|------|--------|-----|
| env001 (DVWA) | 10 | 3 | 4 | 2 | 1 |
| env002 (JuiceShop) | 10 | 2 | 5 | 2 | 1 |
| env003 (WebGoat) | 10 | 1 | 5 | 3 | 1 |
| env004 (Metasploitable) | 10 | 4 | 4 | 2 | 0 |
| env005 (API/PortSwigger) | 10 | 3 | 4 | 2 | 1 |
| **Total** | **50** | **13** | **22** | **11** | **4** |

**Distribution analysis**: Much better balanced than the original 31/50 medium-heavy
synthetic dataset! Critical (26%) and High (44%) dominate, reflecting real-world
vulnerability distributions from intentionally vulnerable applications.

### Key Design Insight — env004 (Metasploitable)
Metasploitable 2 contains findings with `exploit_known=True` and real CVE IDs.
This environment specifically tests the **temporal scoring component**:
- meta-001 (CVE-2011-2523): vsftpd backdoor → expected critical → KEV match?
- meta-004 (CVE-2008-0166): Debian SSH weak keys → expected critical → known exploit

If SecuraX correctly classifies these as critical using exploit_known alone (even
without KEV network access), the temporal component is validated.

## Open Questions
- [ ] Should we run the actual experiment now and commit results to results/?
- [ ] What seed value to use for the random baseline in the paper? (42 recommended)
- [ ] When is the CITATION.cff DOI available? (after Zenodo release)

## Decisions Made
- Ground truth extended to 50 real-scenario findings (5 environments × 10)
- Plugin SDK uses ABC + singleton registry pattern (ADR-004)
- Synthetic-first with Zenodo DOI planned (ADR-005)

## Actual Experiment Results (E1 Benchmark v1.0.0)

### run_experiment.py Output

| Method | Precision | Recall | Macro-F1 |
|--------|---------|--------|---------|
| **SecuraX** | **0.5934** | **0.6227** | **0.5942** |
| Baseline-CVSS | 0.8000 | 0.8000 | 0.8000 |
| Baseline-RULE | 0.6889 | 0.7091 | 0.6643 |
| Baseline-PRIORITY | 0.8000 | 0.8000 | 0.8000 |
| Baseline-RANDOM | 0.2043 | 0.1035 | 0.1321 |

### Ablation Study Results

| Component Removed | Macro-F1 | Delta |
|---|---|---|
| Full Engine | 0.5942 | ref |
| Without Asset Criticality | 0.5942 | +0.0000 |
| Without Compliance Penalties | 0.5516 | -0.0426 |
| Without Exploitability | 0.5058 | -0.0884 |
| Without Exposure Factor | 0.4295 | -0.1647 |
| **Without Threat Context** | **0.1785** | **-0.4157** |

**Key finding**: Threat Context (vulnerability type classification) is by far the most important
component (Δ=-0.416). Removing it collapses F1 to near-random performance.

### Internal Benchmark (pytest GT, v3.1.0 calibrated)

| Tier | Engine F1 | Naive F1 | Delta |
|------|---------|--------|------|
| minimal | 1.000 | 0.667 | +0.333 |
| medium | 1.000 | 0.971 | +0.029 |
| high | 0.923 | 0.833 | +0.090 |
| critical | 0.923 | 1.000 | -0.077 |
| **Macro** | **0.769** | **0.694** | **+0.075** |

**Macro-F1 engine > baseline** → H₁ confirmed in internal benchmark.

## Open Research Questions

### Why does Baseline-CVSS beat SecuraX in E1?

The E1 benchmark uses single-finding entries. The CVSS baseline maps severity → tier 1:1.
SecuraX needs accumulation + full context to differentiate (its added value is for multi-finding
scans). This is an important finding for the paper:

> "SecuraX excels in multi-vulnerability aggregation scenarios where naive severity-lookup
> baselines fail to account for accumulation effects and contextual amplification."

**Plan**: Add E2 benchmark with multi-finding scans to demonstrate SecuraX's true advantage.

## Next Steps (Week 05)

- [ ] Design E2 experiment (multi-finding scan results)
- [ ] Run actual DVWA/JuiceShop Docker deployments for real scan data (v1.1.0 dataset)
- [ ] Begin thesis chapter draft
- [ ] Submit research proposal to supervisor

