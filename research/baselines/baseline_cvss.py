"""
SecuraX Risk Engine Baseline — Naive CVSS-Only
================================================
Maps the highest severity found in scan results to a risk level.
This is the simplest possible risk scorer — a threshold lookup.

The multi-dimensional SecuraX engine must outperform this baseline
to justify its added complexity.

Research use:
    Cited in all SecuraX benchmark results as 'Baseline-CVSS'.

References:
    [CVSS31] FIRST.Org. "Common Vulnerability Scoring System v3.1:
             Specification Document", 2019.
             https://www.first.org/cvss/specification-document
    [NVD]    NIST. "National Vulnerability Database", 2024.
             https://nvd.nist.gov/

Baseline identifier: baseline_cvss
Version: 1.0.0
"""

NAME = "Baseline-CVSS"
VERSION = "1.0.0"
DESCRIPTION = (
    "Naive CVSS-only baseline: classifies risk by highest severity present "
    "in scan results. No contextual adjustment."
)

# CVSS severity → risk level mapping (CVSS v3.1 qualitative scale)
# References: CVSS v3.1 Specification, Section 5 (Qualitative Severity Rating Scale)
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "informational"]
_SEVERITY_TO_RISK = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "minimal",
    "informational": "minimal",
}


def classify(scan_input: dict, **_kwargs) -> str:
    """
    Classify risk level using CVSS severity lookup only.

    All keyword arguments (internet_facing, has_pii, exploit_known, etc.)
    are deliberately ignored — this baseline has no contextual awareness.

    Args:
        scan_input: SecuraX-format scan result dict with 'vulnerabilities' list.
        **_kwargs:  Ignored. Present for interface compatibility.

    Returns:
        Risk level: one of {minimal, low, medium, high, critical}
    """
    vulns = scan_input.get("vulnerabilities", [])

    if not vulns:
        return "minimal"

    severities = {v.get("severity", "info").lower() for v in vulns}

    # Return the highest severity present
    for sev in _SEVERITY_ORDER:
        if sev in severities:
            return _SEVERITY_TO_RISK.get(sev, "minimal")

    return "minimal"


def metadata() -> dict:
    """Return baseline metadata for experiment results."""
    return {
        "name": NAME,
        "version": VERSION,
        "description": DESCRIPTION,
        "contextual_factors": [],
        "references": [
            "https://www.first.org/cvss/specification-document",
            "https://nvd.nist.gov/",
        ],
    }
