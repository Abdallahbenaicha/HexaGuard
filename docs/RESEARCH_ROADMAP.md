# SecuraX — Research Roadmap

> **Version**: 3.0.0 | **Last updated**: 2026-07-31  
> **Engine**: v3.1.0 | **Dataset**: v1.0.0

## Overview

This document defines the open research questions SecuraX addresses, the
experiments designed to answer them, and the publication targets for each
contribution. Every feature must connect to at least one question here.

> [!IMPORTANT]
> **E1 result caveat**: On single-finding classification (E1), Baseline-CVSS
> (macro-F1 = 0.800) outperforms SecuraX (0.594). This is an experimental-design
> mismatch: E1 measures single-finding classification while SecuraX's distinguishing
> components (multi-finding aggregation, attack-chain amplification, KEV decay)
> operate only on multi-finding inputs. See `docs/research/E2_HYPOTHESIS.md`
> for the pre-registered experiment that directly tests the engine's design claim.

---

## Open Research Questions

### RQ1 — Multi-Finding Context Aggregation
> *Does SecuraX's context-aggregation mechanism (geometric-decay + attack-chain
> detection) produce higher macro-F1 than a naive CVSS lookup when inputs contain
> ≥3 correlated findings?*

**Hypothesis**: The accumulation and contextual amplification mechanisms outperform
severity-lookup baselines in realistic multi-finding scenarios.

**Current status**: E1 (single-finding) complete — E1 favors Baseline-CVSS.
E2 (multi-finding) pre-registered; implementation in progress.

**Key result so far**: Ablation shows Threat Context is the primary driver
(Δ = −0.416 when removed); accumulation effects are not testable in E1.

---

### RQ2 — False Positive Rate by Scanner Type
> *What is the empirical FPR for each of the 11 integrated scanner engines?*

**Hypothesis**: DAST (active exploitation) has lower FPR than SAST (static
heuristics) and passive web scanners.

**Measurement**: Manual triage on DVWA, JuiceShop, WebGoat, Metasploitable.

**Current status**: 🔴 Not started | Experiment ID: E-FPR

---

### RQ3 — Attack Chain Detection Accuracy
> *Does the rule-based attack-chain detector in `risk_engine.py` identify
> realistic multi-step attack paths with acceptable precision?*

**Hypothesis**: Keyword-matching approach detects common chains (XSS+no-CSP,
SQLi, RCE+internet) with >80% precision on labelled data.

**Current status**: 🟡 Detector implemented; evaluation dataset not created.
Experiment ID: E-ATK

---

### RQ4 — Remediation Guidance Quality
> *Does ARIA-generated remediation guidance reduce developer time-to-fix?*

**Status**: 🔴 Not started | Requires IRB approval for human subjects study.

---

### RQ5 — Compliance Coverage Completeness
> *How completely does SecuraX map findings to GDPR Art. 32/33, PCI-DSS Req. 6.3,
> and ISO 27001 A.14.2?*

**Status**: 🟡 ARIA produces compliance text; coverage ratio not measured.

---

## Experiment Registry

### E1 — Single-Finding Risk Classification (COMPLETE)

**Status**: ✅ Complete  
**Answers**: Partial RQ1 (single-finding only)  
**Dataset**: `datasets/e1_risk_validation/` — 50 findings, 5 environments  
**Results**: `results/e1_risk_validation/metrics_summary.json`

**Key results (engine v3.0.0, seed=42)**:

| Method | Macro-F1 | Notes |
|--------|---------|-------|
| Baseline-CVSS | **0.800** | Favored by E1 design |
| Baseline-PRIORITY | 0.800 | Tied with CVSS |
| Baseline-RULE | 0.664 | |
| **SecuraX** | **0.594** | See E1 design mismatch note |
| Baseline-RANDOM | 0.132 | Statistical floor |

**Ablation results (E1)**:

| Component Removed | Macro-F1 | Δ |
|---|---|---|
| Full engine | 0.594 | ref |
| Without Compliance | 0.552 | −0.043 |
| Without Exploitability | 0.506 | −0.088 |
| Without Exposure | 0.430 | −0.165 |
| **Without Threat Context** | **0.178** | **−0.416** |

**Interpretation**: Threat Context is the primary driver. The engine's low
performance on E1 is explained by the single-finding evaluation design, not
by the contextual components being unhelpful.

**Reproduce**:
```bash
python research/run_experiment.py --experiment e1 --seed 42
```

---

### E2 — Multi-Finding Aggregation Benchmark (COMPLETE)

**Status**: ✅ Complete (pre-registered 2026-07-31, run 2026-08-01)
**Answers**: RQ1 (core claim)
**Pre-registration**: `docs/research/E2_HYPOTHESIS.md` (committed before run)
**Dataset**: `datasets/e2_multi_finding/` (20 scenarios, 3-12 findings each)
**Results**: `results/e2_risk_validation/metrics_summary.json`

**Key results (engine v3.0.0, seed=42):**

| Method | Macro-F1 | Notes |
|--------|---------|-------|
| **SecuraX** | **0.5167** | H1 confirmed — beats all baselines |
| Baseline-CVSS | 0.3391 | Baseline cannot aggregate |
| Baseline-RULE | 0.3391 | Tied — no accumulation logic |
| Baseline-PRIORITY | 0.3391 | Tied — no accumulation logic |
| Baseline-RANDOM | 0.0900 | Statistical floor |

**H1 confirmed**: SecuraX macro-F1 (0.5167) > Baseline-CVSS (0.3391),
a difference of +0.178 (52.5% relative improvement). All baselines
tie at 0.3391 because they cannot aggregate multi-finding context.

**Per-class SecuraX F1**: minimal=0.0 (engine over-escalates minimal),
low=0.75, medium=0.667, high=0.50, critical=0.667.

**Key weakness**: The engine over-escalates "minimal" scenarios (0 TP, 2 FN).
This is a calibration issue in the accumulation floor — documented as
a known limitation for v3.1.0 weight revision.

**Reproduce**:
```bash
python research/run_experiment.py --experiment e2 --seed 42
```


---

### E-FPR — False Positive Rate Study (PLANNED)

**Status**: 🔴 Not started  
**Answers**: RQ2  
**Dataset**: `datasets/fpr_study/` (planned)  
**Blocker**: Docker deployment of DVWA, JuiceShop, WebGoat, Metasploitable

---

### E-ATK — Attack Chain Detection Accuracy (PLANNED)

**Status**: 🔴 Not started  
**Answers**: RQ3  
**Dataset**: `datasets/attack_chains/` (planned)

---

## Dataset Registry

| Dataset | Experiment | Status | Path |
|---------|-----------|--------|------|
| Synthetic benchmark v1.0.0 | E1 | ✅ | `datasets/e1_risk_validation/` |
| Multi-finding scenarios v1.0.0 | E2 | 🟡 In progress | `datasets/e2_multi_finding/` |
| FPR study | E-FPR | 🔴 Planned | `datasets/fpr_study/` |
| Attack chain scenarios | E-ATK | 🔴 Planned | `datasets/attack_chains/` |

All datasets follow the versioning policy in `docs/DATASETS.md`.

---

## Publication Targets

| Contribution | Venue | Status |
|---|---|---|
| E1+E2 results (RQ1) | IEEE TDSC / USENIX Security (tools track) | 🔴 Not ready |
| Benchmark platform paper | USENIX Security / IEEE S&P tools track | 🟡 In progress |
| RQ3 attack chain paper | ACM SIGSAC Workshop | 🔴 Not ready |
| PhD research proposal | International Cybersecurity Research Labs & Programs | 🟡 Draft |

---

## Publication Readiness Checklist

- [ ] Cite `CITATION.cff` — request DOI via Zenodo
- [ ] Record `risk_engine.VERSION` in all datasets
- [ ] Record scanner versions in scan output
- [ ] Provide Docker environment for reproduction
- [ ] Include `datasets/` with metadata and ground truth
- [ ] Run `make e1` and `make e2` — include results files
- [ ] Review `docs/RISK_ENGINE.md` — all claims must match implementation
- [ ] Include pre-registration document in paper appendix

---

## Contributing to Research

1. Open a GitHub Discussion with your research question
2. Submit experimental datasets to `datasets/` via PR (see `docs/DATASETS.md`)
3. Add your experiment to this document
4. Cite SecuraX using `CITATION.cff`

Contact: `Abdallahbenaichatech@gmail.com`
