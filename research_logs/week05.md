# Week 05 — 2026-08-01 (Current)

## Objectives This Week
- [x] Stage 5: Write CISPA research statement (`papers/cispa_research_statement.md`)
- [x] Stage 4: Prune dead files (generate_manifest.py, e2_fpr_study/, e3_attack_chains/)
- [x] Stage 1a: Write E2 pre-registration document (committed before implementation)
- [x] Stage 1b: Implement E2 dataset (20 multi-finding scenarios, expert-elicited GT)
- [x] Stage 2: Extend `run_experiment.py` for E2 (dispatch loader, load_e2_data)
- [x] Stage 1c: Run E2 experiment — H1 confirmed
- [x] Stage 4: Rewrite RESEARCH_ROADMAP.md with honest E1 framing + E2 results
- [ ] Stage 3: Frontend attack chain panel
- [ ] Stage 6: Final validation + CHANGELOG + git push

## Critical Result: E2 — H1 Confirmed

### The Research Question
Does SecuraX's multi-finding aggregation outperform naive CVSS on realistic
multi-finding scan scenarios?

### Answer: YES (pre-registered)

| Method | Macro-F1 |
|--------|---------|
| **SecuraX** | **0.5167** |
| Baseline-CVSS | 0.3391 |
| Baseline-RULE | 0.3391 |
| Baseline-PRIORITY | 0.3391 |
| Baseline-RANDOM | 0.0900 |

**H1 confirmed**: SecuraX macro-F1 (0.5167) > Baseline-CVSS (0.3391)
Relative improvement: +52.5%

### Why All Baselines Tie at 0.3391
The CVSS-only, Rule, and Priority baselines all rely on the severity of
individual findings. In multi-finding scenarios, they look only at the
worst individual finding (or at simple counts). They cannot model:
- Accumulation: 12 low findings escalating to medium risk
- Attack chains: XSS+CSP-bypass escalating beyond individual finding severity
- KEV amplification: medium finding becoming critical due to known exploit + context

SecuraX's geometric-decay aggregation and contextual multipliers are the
only mechanism that can differentiate these scenarios from the ground truth.

### Per-Class Analysis (SecuraX E2)

| Class | F1 | TP | FP | FN | Analysis |
|---|---|---|---|---|---|
| minimal | 0.00 | 0 | 0 | 2 | Over-escalates minimal: accumulation elevates 2 true-minimal to low |
| low | 0.75 | 3 | 2 | 0 | Good recall; some false positives from medium |
| medium | 0.67 | 3 | 2 | 1 | Solid |
| high | 0.50 | 3 | 2 | 4 | Engine misses high (escalates to critical or not enough) |
| critical | 0.67 | 3 | 2 | 1 | Good on critical; some false positives |

### Known Weaknesses (honest, for paper)
1. **Minimal class (F1=0.0)**: The engine over-escalates truly minimal scenarios.
   Root cause: accumulation floor does not have a "minimal-preserving" gate.
   Even 3 low findings with no internet/PII/payment context push the sigmoid
   above the minimal threshold.
2. **High class (F1=0.50)**: 4 false negatives — engine classifies some "high"
   scenarios as critical (over-escalation) or medium (under-escalation).
3. **N=20 sample**: Statistical power is limited. Bootstrap CI will be wide.
   This is a known limitation stated in the pre-registration document.

### Comparison: E1 vs E2

| Scenario | SecuraX | Baseline-CVSS | Delta |
|---|---|---|---|
| E1 (single-finding) | 0.5942 | 0.8000 | -0.206 (CVSS wins) |
| E2 (multi-finding) | 0.5167 | 0.3391 | +0.178 (SecuraX wins) |

This is the key research finding: the engine's value is
**scenario-dependent** — it underperforms a lookup table on single findings
(as expected) but outperforms all baselines on multi-finding aggregation
(as designed).

## Files Created / Modified

| File | Action | Stage |
|------|--------|-------|
| `papers/cispa_research_statement.md` | NEW | Stage 5 |
| `docs/research/E2_HYPOTHESIS.md` | NEW | Stage 1a |
| `datasets/e2_multi_finding/metadata.json` | NEW | Stage 1b |
| `datasets/e2_multi_finding/ground_truth.json` | NEW | Stage 1b |
| `research/run_experiment.py` | MODIFIED (E2 loader) | Stage 2 |
| `docs/RESEARCH_ROADMAP.md` | REWRITTEN | Stage 4 |
| `datasets/e2_fpr_study/` | DELETED (empty placeholder) | Stage 4 |
| `datasets/e3_attack_chains/` | DELETED (empty placeholder) | Stage 4 |
| `research/generate_manifest.py` | DELETED (dead code) | Stage 4 |
| `results/e2_risk_validation/` | NEW (auto-generated) | Stage 1c |

## Next Steps (Week 06)

- [ ] Stage 3: Frontend attack chain panel + MITRE ATT&CK badges
- [ ] Stage 6: Full validation (make test + make e1 + make e2)
- [ ] Refine CISPA research statement with E2 results
- [ ] Address minimal-class calibration (v3.2.0 ADR)
- [ ] Bootstrap confidence intervals for E2 (N=20 statistical note)
- [ ] Begin thesis/paper draft for E1+E2 combined results
