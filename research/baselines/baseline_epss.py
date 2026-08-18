"""
SecuraX Risk Engine Baseline -- EPSS (Exploit Prediction Scoring System)
=========================================================================
Uses the public EPSS API (first.org) to classify risk based on empirical
exploit probability, rather than CVSS severity alone.

Scoring algorithm:
    For each CVE ID found in the scan input, query the EPSS API and
    retrieve the EPSS score (0.0-1.0). Take the maximum EPSS score
    across all CVEs, then map to a risk tier:

        EPSS >= 0.70  ->  critical
        EPSS >= 0.40  ->  high
        EPSS >= 0.10  ->  medium
        EPSS >= 0.01  ->  low
        EPSS <  0.01  ->  minimal  (valid EPSS result, NOT a fallback)

    CVSS fallback is used ONLY when:
        (a) the scan contains no valid CVE identifier, OR
        (b) the EPSS API request fails / times out, OR
        (c) the CVE is not present in the EPSS response.

    A valid EPSS score below 0.01 maps to 'minimal' -- it is NOT a
    fallback condition. Do NOT substitute CVSS for a valid low EPSS score.

EPSS coverage statistics:
    Accumulated per-run via get_run_stats() / reset_run_stats().
    Experiment runner must call get_run_stats() after all classify() calls
    and include the result in experiment output for disclosure.

Disclosure requirement:
    fallback_rate > 0.50  ->  label as 'Baseline-EPSS (fallback-dominated)'
    fallback_rate > 0.20  ->  label as 'Baseline-EPSS (partial-fallback)'
    fallback_rate <= 0.20 ->  label as 'Baseline-EPSS'

References:
    [Spring2021]  Spring et al. EPSS. IEEE S&P Workshop, 2021.
    [EPSS-API]    https://api.first.org/data/v1/epss
    [Jacobs2021]  Jacobs et al. USENIX Security, 2021.
    [ADR-003]     docs/adr/ADR-003-multi-dimensional-scoring.md

Baseline identifier: baseline_epss
Version: 1.0.0
"""

import re
import logging
from typing import Optional

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

NAME = "Baseline-EPSS"
VERSION = "1.0.0"
DESCRIPTION = (
    "EPSS-based baseline: uses the public first.org EPSS API to classify risk "
    "by empirical exploit probability. CVSS fallback only on API failure or "
    "absent CVE identifiers -- a valid EPSS score of any magnitude is used directly."
)

# -- EPSS API ------------------------------------------------------------------
_EPSS_API_BASE = "https://api.first.org/data/v1/epss"
_REQUEST_TIMEOUT = 10
_CACHE: dict = {}   # CVE-ID -> float or None

# -- EPSS tier mapping ---------------------------------------------------------
# Thresholds from EPSS v3 percentile distributions (first.org/epss, 2024).
# Score < 0.01 -> 'minimal' via this table, NOT a CVSS fallback.
_EPSS_TIERS = [
    (0.70, "critical"),
    (0.40, "high"),
    (0.10, "medium"),
    (0.01, "low"),
    (0.0,  "minimal"),
]

# -- CVSS fallback (same logic as baseline_cvss.py) ---------------------------
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "informational"]
_SEVERITY_TO_RISK = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "minimal",
    "informational": "minimal",
}

# -- Per-run coverage statistics -----------------------------------------------
# All observation-level counts: one unit = one classify() call.
# epss_calls and epss_hits are CVE-API-level (may differ from observation count
# in multi-CVE scans); they are informational only.
_run_stats: dict = {
    "epss_observations":     0,   # classify() calls where EPSS path succeeded
    "fallback_observations": 0,   # classify() calls where CVSS fallback was used
    "epss_calls":            0,   # CVE-level API queries made (unique CVEs, not cache hits)
    "epss_hits":             0,   # CVE-level API queries that returned a score
    "total_calls":           0,   # total classify() calls
}


def reset_run_stats() -> None:
    """Reset per-run coverage statistics. Call before a new experiment run."""
    global _run_stats
    _run_stats = {
        "epss_observations":     0,
        "fallback_observations": 0,
        "epss_calls":            0,
        "epss_hits":             0,
        "total_calls":           0,
    }


def get_run_stats() -> dict:
    """
    Return per-run EPSS coverage statistics with disclosure label.
    Call AFTER all classify() calls to capture final numbers.
    The experiment runner (run_experiment.py L641) calls metadata()
    which calls this function, ensuring coverage is in results JSON.

    Rates are derived from observation-level counts:
      - fallback_rate = fallback_observations / total_calls
      - epss_rate     = epss_observations / total_calls
    epss_calls and epss_hits are CVE-API informational counters only.
    """
    stats = dict(_run_stats)
    total = stats["total_calls"]
    if total > 0:
        stats["epss_rate"]     = round(stats["epss_observations"] / total, 4)
        stats["fallback_rate"] = round(stats["fallback_observations"] / total, 4)
    else:
        stats["epss_rate"]     = None
        stats["fallback_rate"] = None
    fr = stats["fallback_rate"]
    if fr is None:
        label = "Baseline-EPSS (no data)"
    elif fr > 0.50:
        label = "Baseline-EPSS (fallback-dominated)"
    elif fr > 0.20:
        label = "Baseline-EPSS (partial-fallback)"
    else:
        label = "Baseline-EPSS"
    stats["disclosure_label"] = label
    return stats


def _epss_score_for_cve(cve_id: str) -> Optional[float]:
    """
    Query EPSS API for one CVE. Returns float score or None.
    None means: not found in EPSS OR API failed (both are fallback conditions).
    Results cached per-process to avoid redundant API calls.
    """
    cve_id = cve_id.upper().strip()
    if cve_id in _CACHE:
        return _CACHE[cve_id]
    if not _REQUESTS_AVAILABLE:
        logger.warning("requests not installed -- EPSS API unavailable")
        _CACHE[cve_id] = None
        return None
    try:
        resp = requests.get(
            _EPSS_API_BASE,
            params={"cve": cve_id},
            timeout=_REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            score = float(data[0].get("epss", 0.0))
            _CACHE[cve_id] = score
            return score
        # CVE not in EPSS database -- valid not-found
        _CACHE[cve_id] = None
        return None
    except Exception as exc:
        logger.warning("EPSS API error for %s: %s", cve_id, exc)
        _CACHE[cve_id] = None
        return None


def _epss_tier(score: float) -> str:
    """Map EPSS score (0.0-1.0) to risk tier per approved mapping."""
    for threshold, tier in _EPSS_TIERS:
        if score >= threshold:
            return tier
    return "minimal"


def _cvss_fallback(scan_input: dict) -> str:
    """CVSS severity-lookup fallback. Used ONLY on fallback conditions (a/b/c)."""
    vulns = scan_input.get("vulnerabilities", [])
    if not vulns:
        return "minimal"
    severities = {v.get("severity", "info").lower() for v in vulns}
    for sev in _SEVERITY_ORDER:
        if sev in severities:
            return _SEVERITY_TO_RISK.get(sev, "minimal")
    return "minimal"


def _extract_cve_ids(scan_input: dict) -> list:
    """Extract all unique CVE IDs from scan_input vulnerabilities."""
    cve_ids = []
    for v in scan_input.get("vulnerabilities", []):
        raw = v.get("cve_ids") or []
        if isinstance(raw, str):
            raw = re.findall(r"CVE-\d{4}-\d+", raw, re.IGNORECASE)
        for cve in raw:
            cve_str = str(cve).strip()
            if re.match(r"CVE-\d{4}-\d+", cve_str, re.IGNORECASE):
                cve_ids.append(cve_str.upper())
    return list(set(cve_ids))


def classify(scan_input: dict, **_kwargs) -> str:
    """
    Classify risk using EPSS scores from the public first.org API.

    Fallback conditions (CVSS used instead of EPSS):
        (a) No valid CVE identifier in scan_input
        (b) EPSS API fails / times out for ALL CVEs queried
        (c) No queried CVE is present in the EPSS database

    IMPORTANT: A valid EPSS score below 0.01 maps to 'minimal' via the
    EPSS tier table -- this is NOT a CVSS fallback.

    All **_kwargs deliberately ignored -- EPSS does not use env context.
    """
    global _run_stats
    _run_stats["total_calls"] += 1
    cve_ids = _extract_cve_ids(scan_input)

    # Condition (a): no valid CVE identifiers -> CVSS fallback
    if not cve_ids:
        _run_stats["fallback_observations"] += 1
        return _cvss_fallback(scan_input)

    # Query EPSS for each unique CVE (cache prevents duplicate API calls)
    scores = []
    for cve_id in cve_ids:
        if cve_id not in _CACHE:
            _run_stats["epss_calls"] += 1   # actual new API call
        score = _epss_score_for_cve(cve_id)
        if score is not None:
            scores.append(score)

    # Track CVE-level hits separately (informational)
    _run_stats["epss_hits"] += len(scores)

    # Conditions (b) and (c): all CVE queries returned no score
    if not scores:
        _run_stats["fallback_observations"] += 1
        return _cvss_fallback(scan_input)

    # Valid EPSS path: use max score across all successfully retrieved CVEs
    _run_stats["epss_observations"] += 1
    return _epss_tier(max(scores))


def metadata() -> dict:
    """
    Return baseline metadata for experiment results.
    Call AFTER all classify() calls for accurate run_coverage statistics.
    """
    stats = get_run_stats()
    return {
        "name": NAME,
        "version": VERSION,
        "description": DESCRIPTION,
        "api_endpoint": _EPSS_API_BASE,
        "epss_tier_mapping": {
            ">=0.70": "critical",
            ">=0.40": "high",
            ">=0.10": "medium",
            ">=0.01": "low",
            "<0.01":  "minimal (valid EPSS result -- NOT fallback)",
        },
        "fallback_strategy": "cvss_severity_lookup",
        "fallback_trigger": (
            "Fallback to CVSS only when: (a) no valid CVE in scan_input, "
            "(b) EPSS API fails/times out, or (c) CVE not in EPSS database. "
            "A valid EPSS score below 0.01 maps to minimal -- not a fallback."
        ),
        "run_coverage": stats,
        "disclosure": {
            "disclosure_label": stats["disclosure_label"],
            "rule": (
                "fallback_rate > 0.50 -> label as Baseline-EPSS (fallback-dominated). "
                "Such results must not be cited as a pure EPSS evaluation."
            ),
        },
        "contextual_factors": ["cve_ids"],
        "ignored_factors": [
            "internet_facing", "exploit_known", "has_pii",
            "has_payment", "asset_criticality", "kev_integration",
        ],
        "references": [
            "https://api.first.org/data/v1/epss",
            "https://www.first.org/epss",
        ],
    }
