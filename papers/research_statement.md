# SecuraX — Research Statement
### Abdallah Benaicha | innovation.team.dz@gmail.com | Abdallahbenaichatech@gmail.com

## Summary

SecuraX is an open-source, self-hosted security scanning platform that
orchestrates eleven scanner engines (DAST, SAST, network, SSL/TLS, DNS,
dependency, and configuration analysis) behind a unified interface, and
layers a multi-dimensional risk-scoring engine on top of raw findings.
The engine extends CVSS v3.1 with temporal (CISA KEV) and environmental
(asset criticality, exposure, PII/payment presence) adjustment factors,
and aggregates multi-finding context through geometric-decay accumulation
and rule-based attack-chain detection.

The core research contribution is not the platform itself but a
reproducible benchmark, evaluated under a pre-specified protocol
committed to version control before the experiment was run, testing
whether multi-finding context aggregation measurably outperforms
non-aggregating severity-based baselines.

## Key Results

On the evaluated multi-finding benchmark (E2), the proposed aggregation
engine achieved a macro-F1 of 0.517 compared with 0.339 for the strongest
non-aggregating baseline (+52.5% relative). On single-finding
classification (E1), the engine underperforms a lookup-table baseline
(macro-F1 0.594 vs. 0.800); this evaluation loop scores each finding in
isolation with no access to sibling findings, so the aggregation
mechanism cannot exploit multi-finding context in this condition — a
consequence of the evaluation protocol and data flow, verified through
code inspection rather than inferred from the results alone.

An ablation analysis on the single-finding benchmark further showed that
the full engine achieved a macro-F1 of 0.594, whereas removing the
threat-context component alone reduced macro-F1 to 0.178 (Δ = −0.416) —
the largest drop of any component removed — suggesting that contextual
evidence, rather than the scoring architecture alone, accounts for a
substantial share of the observed behavior.

Both experiments were re-executed from the released code and reproduced
the reported metrics exactly.

**Known limitations**: sample size is small (N=50 single-finding
observations, N=20 multi-finding scenarios, each independently
ground-truthed at the scenario level) with no confidence intervals yet;
ground truth was assigned by a single annotator without independent
inter-rater validation; all scenarios are synthetic rather than drawn
from live production scans; the AI-assisted remediation component has
not been empirically evaluated; the observed +52.5% improvement should
be read as pilot evidence, not a generalizable claim, pending statistical
testing.

## Research Questions

| ID  | Question | Status |
|-----|----------|--------|
| RQ1 | Does multi-finding context aggregation outperform non-aggregating severity-based baselines on ≥3 correlated findings? | Evaluated in E2; statistical testing pending |
| RQ2 | What is the empirical false-positive rate per scanner engine type? | Planned (E-FPR) |
| RQ3 | What precision and recall does the rule-based attack-chain detector achieve on documented multi-step attack scenarios? | Partial implementation; evaluation pending |
| RQ4 | Does AI-generated remediation guidance reduce developer time-to-fix? | Requires human-subjects study — engineering-adjacent, optional in short-form statements |
| RQ5 | How completely does the engine map findings to GDPR/PCI-DSS/ISO 27001? | Engineering extension — not a primary PhD research question |

## What Is Good / What Is Weak / What Is Next

**Good**: a non-trivial, ablation-validated risk engine; a reproducible
benchmark with a pre-specified evaluation protocol; transparent reporting
of a negative result (E1) alongside evidence supporting the multi-finding
hypothesis (E2); an open-source research artifact with versioned datasets
and full provenance.

**Weak**: no confidence intervals or significance testing yet;
single-annotator ground truth; fully synthetic scenarios; baselines
limited to CVSS-family heuristics (no EPSS or environmental-CVSS
comparison yet); no adversarial-robustness evaluation of the scoring
engine itself.

**Next 90 days**: (1) independent double annotation of ground truth with
inter-rater agreement (Cohen's κ); (2) paired bootstrap confidence
intervals and effect-size estimates over both benchmarks, resampling at
the scenario level to match the ground-truth structure; (3) a calibrated
learned scorer (starting with logistic regression / gradient boosting) to
complement or replace the rule-based aggregation stage, with no
assumption in advance that it will outperform the current engine; (4) an
adversarial-robustness study, following a pre-registered protocol to be
deposited (e.g., OSF) before execution, probing whether manipulated scan
evidence can induce systematic mis-scoring; (5) frontend visualization with
dynamic attack chain and MITRE ATT&CK mapping.

## Proposed PhD Direction

The candidate is open to multiple viable directions grounded in the same
codebase and benchmark, and will adapt the specific framing to the host
group's research focus: (a) extending the current rule-based risk
aggregation engine into a calibrated, learned scoring model and studying
its robustness against adversarially crafted or mislabeled scan evidence;
(b) explainability of automated security risk decisions; (c) learned
false-positive reduction for SAST/DAST triage; (d) graph-based multi-step
attack-chain inference. All four share the same empirical foundation
(E1/E2, ablation) established in this statement.

---

*All numbers in this document are derived directly from executable code
and were re-executed to confirm exact agreement with the reported
metrics.*
*Repository: github.com/Abdallahbenaicha/HexaGuard*
*Engine version: v3.0.0 | Dataset: v1.0.0 | Experiment: E1/E2, seed=42*
