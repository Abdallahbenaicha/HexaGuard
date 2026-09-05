"""
SecuraX Scanner Schema Conformance Tests
=========================================
These tests verify that:
  1. The scanner output schema validator correctly accepts valid outputs.
  2. The schema validator correctly rejects malformed outputs.
  3. Every scanner type in VALID_SCAN_TYPES is represented in the tests.

These tests do NOT invoke real scanner tools (no network calls, no subprocesses).
They test the schema contract that all scanner modules must satisfy.

To test specific scanner logic (with mocked HTTP), see:
  - tests/test_web_scanner.py
  - tests/test_ssl_scanner.py  (planned)
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.schema import (  # noqa: E402
    SCHEMA_VERSION,
    VALID_SCAN_TYPES,
    VALID_SEVERITIES,
    validate_scan_result,
)

# \u2500\u2500 Helper factories \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

def _valid_vuln(**overrides) -> dict:
    """Return a minimally valid vulnerability dict."""
    base = {
        "severity":    "high",
        "check":       "test_check",
        "title":       "Test Finding",
        "description": "A test vulnerability description.",
    }
    base.update(overrides)
    return base


def _valid_result(scan_type: str = "web", vulns: list | None = None) -> dict:
    """Return a minimally valid scan result dict."""
    return {
        "scan_type":        scan_type,
        "target":           "https://example.com",
        "vulnerabilities":  vulns if vulns is not None else [],
        "scanner_versions": {"test_tool": "1.0.0"},
        "scan_duration_s":  1.5,
        "timestamp":        "2026-07-30T05:00:00Z",
    }


# \u2500\u2500 Schema metadata \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestSchemaMetadata:
    def test_schema_version_is_semver(self):
        parts = SCHEMA_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_valid_scan_types_is_non_empty_set(self):
        assert isinstance(VALID_SCAN_TYPES, frozenset)
        assert len(VALID_SCAN_TYPES) >= 11

    def test_valid_severities_contains_expected_values(self):
        assert VALID_SEVERITIES == frozenset({"critical", "high", "medium", "low", "info"})


# \u2500\u2500 Valid results \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestValidResults:
    def test_empty_vulnerabilities_is_valid(self):
        result = _valid_result(vulns=[])
        # Only reproducibility warnings, no hard errors
        errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
        assert errors == []

    def test_single_valid_vulnerability(self):
        result = _valid_result(vulns=[_valid_vuln()])
        errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
        assert errors == []

    def test_all_severity_levels_accepted(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            result = _valid_result(vulns=[_valid_vuln(severity=sev)])
            errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
            assert errors == [], f"Severity '{sev}' should be valid"

    def test_all_scan_types_accepted(self):
        for scan_type in VALID_SCAN_TYPES:
            result = _valid_result(scan_type=scan_type)
            errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
            assert errors == [], f"scan_type '{scan_type}' should be valid"

    def test_optional_fields_accepted(self):
        vuln = _valid_vuln(
            evidence="HTTP/1.1 200 OK\nServer: Apache",
            cve_ids=["CVE-2021-44228"],
            cwe_id="CWE-502",
            owasp_category="A08:2021-Software and Data Integrity Failures",
            mitre_attack="T1190",
            cvss_score=9.8,
            remediation="Upgrade to log4j 2.17.1+",
            false_positive=False,
        )
        result = _valid_result(vulns=[vuln])
        errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
        assert errors == []

    def test_cvss_score_boundary_values(self):
        for score in (0.0, 5.0, 10.0):
            result = _valid_result(vulns=[_valid_vuln(cvss_score=score)])
            errors = [e for e in validate_scan_result(result) if "WARNING" not in e]
            assert errors == [], f"cvss_score {score} should be valid"


# \u2500\u2500 Invalid results \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestInvalidResults:
    def test_non_dict_result_rejected(self):
        errors = validate_scan_result("not a dict")
        assert len(errors) == 1
        assert "dict" in errors[0]

    def test_missing_scan_type(self):
        result = _valid_result()
        del result["scan_type"]
        errors = validate_scan_result(result)
        assert any("scan_type" in e for e in errors)

    def test_invalid_scan_type(self):
        result = _valid_result(scan_type="unknown_scanner")
        errors = validate_scan_result(result)
        assert any("scan_type" in e for e in errors)

    def test_missing_target(self):
        result = _valid_result()
        del result["target"]
        errors = validate_scan_result(result)
        assert any("target" in e for e in errors)

    def test_empty_target_rejected(self):
        result = _valid_result()
        result["target"] = "   "
        errors = validate_scan_result(result)
        assert any("target" in e for e in errors)

    def test_missing_vulnerabilities_field(self):
        result = _valid_result()
        del result["vulnerabilities"]
        errors = validate_scan_result(result)
        assert any("vulnerabilities" in e for e in errors)

    def test_vulnerabilities_not_a_list(self):
        result = _valid_result()
        result["vulnerabilities"] = "not a list"
        errors = validate_scan_result(result)
        assert any("list" in e for e in errors)


class TestInvalidVulnerabilities:
    def test_vuln_not_a_dict(self):
        result = _valid_result(vulns=["not a dict"])
        errors = validate_scan_result(result)
        assert any("dict" in e for e in errors)

    def test_missing_severity(self):
        vuln = _valid_vuln()
        del vuln["severity"]
        result = _valid_result(vulns=[vuln])
        errors = validate_scan_result(result)
        assert any("severity" in e for e in errors)

    def test_invalid_severity_value(self):
        result = _valid_result(vulns=[_valid_vuln(severity="extreme")])
        errors = validate_scan_result(result)
        assert any("severity" in e for e in errors)

    def test_missing_check(self):
        vuln = _valid_vuln()
        del vuln["check"]
        result = _valid_result(vulns=[vuln])
        errors = validate_scan_result(result)
        assert any("check" in e for e in errors)

    def test_missing_title(self):
        vuln = _valid_vuln()
        del vuln["title"]
        result = _valid_result(vulns=[vuln])
        errors = validate_scan_result(result)
        assert any("title" in e for e in errors)

    def test_missing_description(self):
        vuln = _valid_vuln()
        del vuln["description"]
        result = _valid_result(vulns=[vuln])
        errors = validate_scan_result(result)
        assert any("description" in e for e in errors)

    def test_cvss_score_out_of_range_rejected(self):
        result = _valid_result(vulns=[_valid_vuln(cvss_score=11.0)])
        errors = validate_scan_result(result)
        assert any("cvss_score" in e for e in errors)

    def test_cvss_score_negative_rejected(self):
        result = _valid_result(vulns=[_valid_vuln(cvss_score=-0.1)])
        errors = validate_scan_result(result)
        assert any("cvss_score" in e for e in errors)

    def test_cve_ids_not_a_list_rejected(self):
        result = _valid_result(vulns=[_valid_vuln(cve_ids="CVE-2021-44228")])
        errors = validate_scan_result(result)
        assert any("cve_ids" in e for e in errors)

    def test_multiple_vulns_multiple_errors_reported(self):
        result = _valid_result(vulns=[
            _valid_vuln(severity="invalid1"),
            _valid_vuln(severity="invalid2"),
        ])
        errors = validate_scan_result(result)
        severity_errors = [e for e in errors if "severity" in e]
        assert len(severity_errors) >= 2


# \u2500\u2500 Reproducibility warnings \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestReproducibilityWarnings:
    def test_missing_scanner_versions_produces_warning(self):
        result = _valid_result()
        result["scanner_versions"] = {}
        errors = validate_scan_result(result)
        assert any("REPRODUCIBILITY WARNING" in e and "scanner_versions" in e for e in errors)

    def test_missing_timestamp_produces_warning(self):
        result = _valid_result()
        result["timestamp"] = ""
        errors = validate_scan_result(result)
        assert any("REPRODUCIBILITY WARNING" in e and "timestamp" in e for e in errors)

    def test_warnings_do_not_block_valid_result(self):
        """Reproducibility warnings are non-fatal \u2014 they should not appear in
        the hard-error count when the result is otherwise structurally valid."""
        result = _valid_result()
        result["scanner_versions"] = {}
        result["timestamp"] = ""
        all_errors = validate_scan_result(result)
        hard_errors = [e for e in all_errors if "WARNING" not in e]
        assert hard_errors == []
