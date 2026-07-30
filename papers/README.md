# Papers & Publications

> This directory is the **publication factory** for SecuraX research.

## Structure

```
papers/
├── README.md                    ← this file
├── references.bib               ← unified BibTeX bibliography
├── proposal/
│   └── research_proposal.md     ← research proposal (conference / grant)
├── thesis/
│   ├── README.md
│   ├── main.tex                 ← main LaTeX file (placeholder)
│   └── chapters/                ← chapter drafts
├── conference/
│   ├── README.md
│   └── draft_ieee.md            ← conference paper draft (IEEE format)
└── figures/
    └── README.md                ← generated figures land here
```

---

## Publication Targets

| Paper | Venue | Status |
|-------|-------|--------|
| SecuraX Platform Paper | USENIX Security Tools Track | 🔴 Draft phase |
| RQ1+RQ2 (Risk + FPR) | IEEE TDSC | 🔴 Awaiting E1 + E2 data |
| RQ1 Short | ACM CCS Poster | 🔴 Awaiting E1 data |
| RQ3 (Attack Chains) | ACM SIGSAC Workshop | 🟡 Partially done |
| RQ5 (Compliance) | IEEE S&P Workshops | 🟡 In progress |

---

## Pre-Submission Checklist

Before submitting any paper using SecuraX data:

- [ ] `risk_engine.VERSION` recorded in all reported results
- [ ] Dataset version recorded (`datasets/VERSION`)
- [ ] SHA-256 manifest verified (`datasets/dataset-vX.Y.Z-manifest.json`)
- [ ] `CITATION.cff` updated with paper DOI after acceptance
- [ ] Figures generated from `research/figures/generate_figures.py`
- [ ] LaTeX tables from `research/run_experiment.py` (paper_tables/)
- [ ] All baselines reported (SecuraX, CVSS, Rule, Priority, Random)
- [ ] Ablation study included (Table 3 from `research/ablation_study.py`)
- [ ] Threat model referenced (`docs/THREAT_MODEL.md`)
- [ ] ADRs referenced for major design decisions

---

## Cite This Work

```bibtex
@misc{securax2026,
  author    = {Benaicha, Abdallah},
  title     = {{SecuraX}: A Multi-Dimensional Vulnerability Risk Prioritization Platform},
  year      = {2026},
  publisher = {GitHub},
  url       = {https://github.com/Abdallahbenaicha/HexaGuard},
  note      = {PFE Master thesis project, University [redacted for blind review]}
}
```

See `references.bib` for the complete bibliography.
