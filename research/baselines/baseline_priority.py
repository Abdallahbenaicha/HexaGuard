"""
SecuraX Risk Engine Baseline — Priority-Based (CVSS + Asset Criticality)
=========================================================================
A more advanced baseline that combines CVSS severity with asset criticality
but WITHOUT temporal factors (no exploit_known, no KEV, no attack chains).

This tests a specific ablation: the value of temporal context.
If SecuraX (with KEV + exploit_known) beats this baseline, temporal factors
are justified as a meaningful contributor.

Scoring algorithm:
    base_score  = CVSS severity score (critical=9.0, high=7.0, med=4.5, low=2.0)
    asset_mult  = asset_criticality multiplier (critical=1.3, high=1.2, med=1.0, low=0.8)
    final_score = max(vulnerability scores) × asset_mult

    Thresholds: [0,1) minimal | [1,4) low | [4,7) medium | [7,9) high | [9,∞) critical

Research use:
    Cited in all SecuraX benchmark results as 'Baseline-Priority'.
    Simulates a "CVSS + asset inventory" approach (NIST RMF Phase 2).

References:
    [NIST-RMF] NIST. "Risk Management Framework for Information Systems
               and Organizations (SP 800-37r2)", 2018.
               https://doi.org/10.6028/NIST.SP.800-37r2
    [FAIR]     The Open Group. "Factor Analysis of Information Risk (FAIR)", 2009.

Baseline identifier: baseline_priority
Version: 1.0.0
"""

NAME = "Baseline-Priority"
VERSION = "1.0.0"
DESCRIPTION = (
    "Priority-based baseline: CVSS severity + asset criticality, "
    "without temporal factors (no KEV, no exploit_known, no attack chains)."
)

# Base scores per CVSS severity (conservative mapping)
# References: CVSS v3.1 Specification, Table 14 (Qualitative Rating Scale)
_SEV_SCORES = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
    "informational": 0.0,
}

# Asset criticality multipliers
# References: NIST SP 800-37r2, Appendix D (Asset Valuation)
_CRITICALITY_MULT = {
    "critical": 1.30,
    "high":     1.20,
    "medium":   1.00,
    "low":      0.80,
    "minimal":  0.70,
}

_SCORE_THRESHOLDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (1.0, "low"),
    (0.0, "minimal"),
]


def classify(scan_input: dict, **kwargs) -> str:
    """
    Classify risk using CVSS severity + asset criticality multiplier.

    Temporal factors (exploit_known, has_pii, has_payment, compliance)
    are deliberately excluded to isolate their contribution.

    Args:
        scan_input:         SecuraX-format scan result dict.
        **kwargs:           Uses 'asset_criticality' only.

    Returns:
        Risk level: one of {minimal, low, medium, high, critical}
    """
    vulns = scan_input.get("vulnerabilities", [])
    asset_criticality = kwargs.get("asset_criticality", "medium")

    if not vulns:
        return "minimal"

    # Compute maximum base score across all findings
    max_base = max(
        _SEV_SCORES.get(v.get("severity", "info").lower(), 0.0)
        for v in vulns
    )

    # Apply asset criticality multiplier
    mult = _CRITICALITY_MULT.get(asset_criticality.lower(), 1.0)
    final_score = min(max_base * mult, 10.0)

    # Threshold lookup
    for threshold, level in _SCORE_THRESHOLDS:
        if final_score >= threshold:
            return level

    return "minimal"


def metadata() -> dict:
    """Return baseline metadata for experiment results."""
    return {
        "name": NAME,
        "version": VERSION,
        "description": DESCRIPTION,
        "contextual_factors": ["severity_scores", "asset_criticality"],
        "excluded_factors": [
            "internet_facing",
            "exploit_known",
            "kev_integration",
            "has_pii",
            "has_payment",
            "attack_chains",
        ],
        "references": [
            "https://doi.org/10.6028/NIST.SP.800-37r2",
            "https://www.first.org/cvss/specification-document",
        ],
    }
