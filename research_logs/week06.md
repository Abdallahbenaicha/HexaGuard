# Week 06 — 2026-08-16

## Objectives This Week
- [x] Stage F: Generate missing figures (fig5, fig7, fig8) — `research/figures/generate_figures.py`
- [x] Stage F: Fix NumPy RuntimeWarning in confusion matrix normalisation
- [x] Stage C: Update CISPA research statement with E2 completion + honest weakness list
- [x] Stage 3: Frontend `AttackChainPanel` component + MITRE ATT&CK badges
- [x] Stage 6: Full validation (`pytest` 61/61 ✅ | E1 SecuraX=0.5942 ✅ | E2 SecuraX=0.5167 ✅)
- [ ] Bootstrap confidence intervals for E2 (N=20 statistical note)
- [ ] Begin paper draft sections (Abstract + Section 3 Methodology)

---

## Figures — All 8 Generated

All 8 planned publication figures are now in `papers/figures/`:

| Figure | File | Description | Status |
|--------|------|-------------|--------|
| fig0 | `fig0_summary_dashboard.png` | 2×2 summary dashboard (E1+E2) | ✅ |
| fig2 | `fig2_risk_pipeline.png` | Risk scoring pipeline flowchart | ✅ |
| fig3 | `fig3_dataset_stats.png` | Dataset distribution by environment | ✅ |
| fig4 | `fig4_f1_comparison.png` | F1: SecuraX vs all baselines | ✅ |
| fig5 | `fig5_confusion_matrix.png` | Confusion matrix (E1, row-normalised) | ✅ NEW |
| fig6 | `fig6_ablation.png` | Ablation component contributions | ✅ |
| fig7 | `fig7_precision_recall.png` | Precision/Recall E1 vs E2 | ✅ NEW |
| fig8 | `fig8_roc.png` | Estimated ROC curves (E1, one-vs-rest) | ✅ NEW |

**Note on fig8 (ROC)**: True ROC curves require per-sample continuous scores.
Since `metrics_summary.json` stores only TP/FP/FN, the ROC is estimated from
the single operating point using the method of Fawcett (2006). This is disclosed
in the figure caption and in the code comment.

---

## CISPA Research Statement — Updated

Updated `papers/cispa_research_statement.md`:
- Removed "E2 not yet run" (now complete)
- Added honest weakness list: synthetic GT, N=20 power, minimal-class gap
- Updated "Next 90 days" to reflect actual remaining work
- Fixed engine version footer (was incorrectly v3.1.0, corrected to v3.0.0)

---

## Key Numbers (Consolidated)

| Experiment | SecuraX | Best Baseline | Δ | Conclusion |
|------------|---------|--------------|---|------------|
| E1 (n=50, single-finding) | 0.594 | 0.800 (CVSS) | −0.206 | CVSS wins — expected (lookup ≡ GT) |
| E2 (n=20, multi-finding) | **0.517** | 0.339 (all tied) | **+0.178** | **H1 confirmed** |

**Ablation**: Removing threat-context drops from 0.594 → 0.178 (Δ=0.416).

---

## Known Technical Debt

| Issue | Priority | ADR |
|-------|----------|-----|
| Minimal-class F1=0.0 (over-escalation) | Medium | v3.2.0 — add accumulation floor gate |
| E2 N=20 — no bootstrap CI | Medium | Planned: `scipy.stats.bootstrap` |
| True ROC (requires per-sample scores) | Low | Store scores in `scan_jobs` table |
| seaborn not installed in production | Low | Add to `requirements.txt` optional extras |

---

## Next Steps (Week 07)

- [ ] Frontend: attack chain panel component + MITRE ATT&CK badge renderer
- [ ] Bootstrap CI for E2 (add to `run_experiment.py --bootstrap`)
- [ ] Begin paper draft: Abstract + Problem Statement + Methodology
- [ ] Run full validation pipeline (`make test && make e1 && make e2`)
- [ ] Respond to CHANGELOG + git push with signed commit
