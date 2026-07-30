"""
SecuraX Risk Engine Baseline — Rule-Based
==========================================
A rule-based risk classifier that applies fixed heuristics without
temporal or environmental context. More sophisticated than CVSS-only
but simpler than SecuraX's multi-dimensional engine.

Rules applied (in order):
  1. Any critical severity → critical
  2. High severity + internet_facing → high
  3. Multiple high findings → high
  4. Single high finding → high
  5. Multiple medium findings → medium
  6. Single medium + internet_facing → medium
  7. Single medium (internal) → low
  8. Only low/info → low
  9. No findings → minimal

Research use:
    Cited in all SecuraX benchmark results as 'Baseline-Rule'.
    This simulates a "security analyst checklist" approach.

References:
    [OWASP-RRM] OWASP Foundation. "OWASP Risk Rating Methodology", 2021.
                https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
    [ISO27005]  ISO/IEC 27005:2022 — Information security risk management.

Baseline identifier: baseline_rule
Version: 1.0.0
"""

NAME = "Baseline-Rule"
VERSION = "1.0.0"
DESCRIPTION = (
    "Rule-based baseline: applies fixed heuristics (severity counts + "
    "internet_facing flag) without temporal or full environmental context."
)


def classify(scan_input: dict, **kwargs) -> str:
    """
    Classify risk level using fixed rule-based heuristics.

    Uses only: severity levels, finding counts, and internet_facing flag.
    Does NOT use: exploit_known, has_pii, has_payment, asset_criticality,
    compliance context, or KEV integration.

    Args:
        scan_input:     SecuraX-format scan result dict.
        **kwargs:       Accepts internet_facing only (all others ignored).

    Returns:
        Risk level: one of {minimal, low, medium, high, critical}
    """
    vulns = scan_input.get("vulnerabilities", [])
    internet_facing = kwargs.get("internet_facing", False)

    if not vulns:
        return "minimal"

    severities = [v.get("severity", "info").lower() for v in vulns]

    counts = {
        "critical": severities.count("critical"),
        "high":     severities.count("high"),
        "medium":   severities.count("medium"),
        "low":      severities.count("low"),
    }

    # Rule 1: Any critical → critical
    if counts["critical"] > 0:
        return "critical"

    # Rule 2: High + internet-facing → high
    if counts["high"] > 0 and internet_facing:
        return "high"

    # Rule 3: Multiple high → high
    if counts["high"] >= 2:
        return "high"

    # Rule 4: Single high → high
    if counts["high"] == 1:
        return "high"

    # Rule 5: Multiple medium → medium
    if counts["medium"] >= 3:
        return "medium"

    # Rule 6: Medium + internet-facing → medium
    if counts["medium"] >= 1 and internet_facing:
        return "medium"

    # Rule 7: Medium internal → low
    if counts["medium"] >= 1:
        return "low"

    # Rule 8: Only low/info
    if counts["low"] > 0:
        return "low"

    return "minimal"


def metadata() -> dict:
    """Return baseline metadata for experiment results."""
    return {
        "name": NAME,
        "version": VERSION,
        "description": DESCRIPTION,
        "contextual_factors": ["internet_facing", "finding_counts"],
        "references": [
            "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
            "https://www.iso.org/standard/80585.html",
        ],
    }
