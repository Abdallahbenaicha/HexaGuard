"""
SecuraX Scanner Output Schema \u2014 v1.0
======================================
This module defines and validates the canonical output schema for all
SecuraX scanner engines.

Every scanner module must return a dict conforming to ScanResult.
Every finding within that dict must conform to Vulnerability.

Usage:
    # In a scanner module, after assembling the result:
    from scanners.schema import validate_scan_result, SCHEMA_VERSION
    errors = validate_scan_result(result)
    if errors:
        logger.warning("Schema validation errors: %s", errors)

    # In tests, to assert conformance:
    from scanners.schema import validate_scan_result
    assert validate_scan_result(result) == [], f"Schema errors: {errors}"

Schema version history:
    1.0.0 (2026-07-30): Initial formal schema definition.

Research note:
    This schema is the reproducibility contract for all SecuraX datasets.
    Changes to REQUIRED fields constitute a breaking change and must increment
    SCHEMA_VERSION. Optional fields may be added without incrementing the version.
    All datasets must record SCHEMA_VERSION alongside risk_engine.VERSION.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

#: Semantic version of the scanner output schema.
#: Record this value in all dataset metadata files.
SCHEMA_VERSION: str = "1.0.0"

#: Valid scan type identifiers (matches _SCAN_TYPE_WEIGHT in risk_engine.py)
VALID_SCAN_TYPES: frozenset[str] = frozenset({
    "web",
    "dast",
    "sast",
    "network_ext",
    "network_int",
    "ssl",
    "dependencies",
    "server_int",
    "server_ext",
    "docker",
    "dns",
    "wordpress",
})


class Severity(str, Enum):
    """
    Vulnerability severity levels, aligned with CVSS v3.1 severity bands.

    References:
        CVSS v3.1 Specification Document, Section 5:
        https://www.first.org/cvss/specification-document
    """
    CRITICAL = "critical"  # CVSS 9.0\u201310.0
    HIGH     = "high"      # CVSS 7.0\u20138.9
    MEDIUM   = "medium"    # CVSS 4.0\u20136.9
    LOW      = "low"       # CVSS 0.1\u20133.9
    INFO     = "info"      # CVSS 0.0 / informational


VALID_SEVERITIES: frozenset[str] = frozenset(s.value for s in Severity)


@dataclass
class Vulnerability:
    """
    A single vulnerability finding produced by a SecuraX scanner engine.

    Fields marked REQUIRED must be present and non-empty in every finding.
    Fields marked OPTIONAL may be absent or None without failing schema validation.
    """
    # REQUIRED
    severity:       str   # one of VALID_SEVERITIES
    check:          str   # machine-readable check identifier
    title:          str   # short human-readable title
    description:    str   # full description of the finding

    # OPTIONAL \u2014 enrich findings with standard taxonomy identifiers
    evidence:       Optional[str]  = None  # proof (HTTP response, code line, etc.)
    cve_ids:        list[str]      = field(default_factory=list)
    cwe_id:         Optional[str]  = None  # e.g. "CWE-79"
    owasp_category: Optional[str]  = None  # e.g. "A03:2021-Injection"
    mitre_attack:   Optional[str]  = None  # e.g. "T1190"
    cvss_score:     Optional[float] = None  # 0.0\u201310.0 from NVD
    remediation:    Optional[str]  = None  # actionable fix guidance
    false_positive: bool           = False  # manually triaged


@dataclass
class ScanResult:
    """
    The canonical output of a SecuraX scanner engine.

    All scanner modules must produce a dict that can be validated against
    this structure using validate_scan_result().
    """
    # REQUIRED
    scan_type:        str           # one of VALID_SCAN_TYPES
    target:           str           # scanned target (URL, IP, file path, etc.)
    vulnerabilities:  list[Vulnerability]

    # REQUIRED for reproducibility (should be populated by every scanner)
    scanner_versions: dict[str, str]  = field(default_factory=dict)
    scan_duration_s:  float           = 0.0
    timestamp:        str             = ""   # ISO 8601 UTC

    # OPTIONAL
    engine_version:   Optional[str]   = None  # risk_engine.VERSION at scan time
    error:            Optional[str]   = None  # error message if scan partially failed
    metadata:         dict            = field(default_factory=dict)


# \u2500\u2500 Validation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

def validate_scan_result(result: dict) -> list[str]:
    """
    Validate a scanner output dict against the SecuraX schema.

    Returns a list of error strings. An empty list means the result is valid.

    This function is intentionally non-raising: scanner modules should
    log warnings on schema errors but never crash due to validation failure.

    Args:
        result: A dict produced by a scanner engine.

    Returns:
        List of human-readable error descriptions. Empty if valid.

    Example::

        errors = validate_scan_result(scan_output)
        if errors:
            for e in errors:
                logger.warning("Schema error: %s", e)
    """
    errors: list[str] = []

    if not isinstance(result, dict):
        return ["result must be a dict"]

    # \u2500\u2500 Top-level required fields \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    scan_type = result.get("scan_type")
    if not scan_type:
        errors.append("Missing required field: 'scan_type'")
    elif scan_type not in VALID_SCAN_TYPES:
        errors.append(
            f"Invalid scan_type '{scan_type}'. "
            f"Must be one of: {sorted(VALID_SCAN_TYPES)}"
        )

    target = result.get("target")
    if not target or not isinstance(target, str) or not target.strip():
        errors.append("Missing or empty required field: 'target'")

    if "vulnerabilities" not in result:
        errors.append("Missing required field: 'vulnerabilities'")
    elif not isinstance(result["vulnerabilities"], list):
        errors.append("'vulnerabilities' must be a list")
    else:
        for i, vuln in enumerate(result["vulnerabilities"]):
            vuln_errors = _validate_vulnerability(vuln, index=i)
            errors.extend(vuln_errors)

    # \u2500\u2500 Reproducibility fields (warnings, not hard errors) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    if not result.get("scanner_versions"):
        errors.append(
            "REPRODUCIBILITY WARNING: 'scanner_versions' is empty or missing. "
            "Record tool versions to enable dataset reproduction."
        )

    if not result.get("timestamp"):
        errors.append(
            "REPRODUCIBILITY WARNING: 'timestamp' is missing. "
            "Record ISO 8601 UTC timestamp for dataset traceability."
        )

    return errors


def _validate_vulnerability(vuln: object, index: int) -> list[str]:
    """Validate a single vulnerability dict. Returns a list of errors."""
    errors: list[str] = []
    prefix = f"vulnerabilities[{index}]"

    if not isinstance(vuln, dict):
        return [f"{prefix}: must be a dict, got {type(vuln).__name__}"]

    # Required fields
    for field_name in ("severity", "check", "title", "description"):
        val = vuln.get(field_name)
        if val is None:
            errors.append(f"{prefix}: Missing required field '{field_name}'")
        elif not isinstance(val, str):
            errors.append(f"{prefix}: '{field_name}' must be a string")
        elif not val.strip():
            errors.append(f"{prefix}: '{field_name}' must not be empty")

    severity = vuln.get("severity", "")
    if isinstance(severity, str) and severity and severity.lower() not in VALID_SEVERITIES:
        errors.append(
            f"{prefix}: Invalid severity '{severity}'. "
            f"Must be one of: {sorted(VALID_SEVERITIES)}"
        )

    # Optional but typed fields
    cve_ids = vuln.get("cve_ids")
    if cve_ids is not None and not isinstance(cve_ids, list):
        errors.append(f"{prefix}: 'cve_ids' must be a list if present")

    cvss_score = vuln.get("cvss_score")
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if not (0.0 <= score <= 10.0):
                errors.append(f"{prefix}: 'cvss_score' must be in [0.0, 10.0]")
        except (TypeError, ValueError):
            errors.append(f"{prefix}: 'cvss_score' must be a float if present")

    return errors
