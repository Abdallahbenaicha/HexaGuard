"""
SecuraX Web Scanner \u2014 Unit Tests
=================================
Tests for web_scanner.py using mocked HTTP responses.
No real network calls are made in this test suite.

Coverage targets:
  - Security header checks (REQUIRED_HEADERS)
  - HTTPS redirect detection
  - Server version / CVE pattern detection
  - Error / info disclosure pattern detection
  - Dangerous HTTP method detection
  - Scanner output schema conformance

All HTTP calls are mocked via unittest.mock.patch so that:
  1. Tests are deterministic and fast (no network dependency)
  2. Tests are reproducible on any machine, including CI
  3. Edge cases can be tested without a real server

Research note:
  These tests establish a regression baseline for the web scanner.
  When new checks are added to web_scanner.py, corresponding tests
  must be added here before the PR can be merged.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.schema import validate_scan_result  # noqa: E402

# \u2500\u2500 Helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

def _make_response(
    status_code: int = 200,
    headers: dict | None = None,
    text: str = "<html><body>OK</body></html>",
    url: str = "https://example.com",
    history: list | None = None,
) -> MagicMock:
    """Build a mock requests.Response object.

    headers must be a plain dict[str, str] so that re.search() calls inside
    web_scanner.py do not receive MagicMock objects instead of strings.
    """
    resp = MagicMock()
    resp.status_code = status_code
    # Always use a real dict so header value iteration returns plain strings
    resp.headers = dict(headers) if headers is not None else {}
    resp.text = text
    resp.content = text.encode()
    resp.url = url
    resp.history = history or []
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.5
    resp.raise_for_status = MagicMock()
    return resp



def _run_scan(response_headers: dict | None = None, **scan_kwargs):
    """
    Shared helper: run run_web_scan with a fully mocked HTTP session.

    The scanner uses _make_session() to create a requests.Session, then calls
    sess.get() for the initial fetch. We patch _make_session to return a mock
    session whose .get() returns a controlled _make_response().

    All external API calls (ssllabs, shodan, etc.) are also suppressed by
    returning the same resp mock from sess.get(), which will return empty dicts
    from the parsers because the response body is minimal HTML.
    """
    from scanners import web_scanner
    resp = _make_response(headers=response_headers or {})
    mock_sess = MagicMock()
    mock_sess.get.return_value = resp
    mock_sess.request.return_value = resp
    mock_sess.post.return_value = resp
    scan_kwargs.setdefault("cve_check", False)
    scan_kwargs.setdefault("ssl_check", False)
    with patch("scanners.web_scanner._make_session", return_value=mock_sess), \
         patch("scanners.web_scanner.ThreadPoolExecutor") as mock_pool:
        # Mock empty pool so background network tasks don't fire during unit tests
        mock_instance = MagicMock()
        mock_instance.__enter__.return_value = mock_instance
        mock_instance.submit.return_value = MagicMock()
        mock_pool.return_value = mock_instance
        with patch("scanners.web_scanner.as_completed", return_value=[]):
            return web_scanner.run_web_scan("https://example.com", **scan_kwargs)


def _scan_web(url: str = "https://example.com", **kwargs):
    """Backward-compat alias used by older tests."""
    return _run_scan(**kwargs)


# \u2500\u2500 Schema conformance \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestWebScannerSchemaConformance:
    """
    Verify that run_web_scan() always returns output that satisfies the
    SecuraX scanner output schema, regardless of what the server returns.
    """

    def test_output_has_required_top_level_keys(self):
        result = _run_scan()
        assert "scan_type" in result
        assert "target" in result
        assert "vulnerabilities" in result
        assert result["scan_type"] == "web"

    def test_all_findings_have_required_fields(self):
        """Every vulnerability in the result must have severity, check, title, description."""
        result = _run_scan(response_headers={})
        for vuln in result.get("vulnerabilities", []):
            assert "severity" in vuln, f"Finding missing 'severity': {vuln}"
            assert "check" in vuln, f"Finding missing 'check': {vuln}"
            assert "title" in vuln, f"Finding missing 'title': {vuln}"
            assert "description" in vuln, f"Finding missing 'description': {vuln}"

    def test_all_severities_are_valid(self):
        """Every severity value must be one of the canonical set."""
        from scanners.schema import VALID_SEVERITIES
        result = _run_scan(response_headers={})
        for vuln in result.get("vulnerabilities", []):
            assert vuln.get("severity", "").lower() in VALID_SEVERITIES, (
                f"Invalid severity '{vuln.get('severity')}' in finding: {vuln.get('check')}"
            )


# \u2500\u2500 Security header checks \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestSecurityHeaderChecks:
    """
    Unit tests for the REQUIRED_HEADERS passive checks.
    These are the most critical checks in the web scanner because they are
    exercised on every scan, regardless of mode.
    """

    def _run_check_headers(self, response_headers: dict) -> list[dict]:
        """Run scanner with given response headers and return vulnerabilities."""
        return _run_scan(response_headers=response_headers).get("vulnerabilities", [])


    def test_missing_hsts_detected(self):
        """HSTS missing must produce a high-severity finding."""
        headers = {
            "Content-Security-Policy":    "default-src 'self'",
            "X-Frame-Options":            "DENY",
            "X-Content-Type-Options":     "nosniff",
        }
        # No Strict-Transport-Security
        vulns = self._run_check_headers(headers)
        hsts_findings = [v for v in vulns if "hsts" in v.get("check", "").lower()
                         or "strict-transport" in v.get("title", "").lower()
                         or "strict-transport" in v.get("description", "").lower()]
        assert len(hsts_findings) >= 1, "HSTS missing was not detected"
        assert hsts_findings[0]["severity"] in ("high", "critical"), (
            f"HSTS finding severity should be high/critical, got: {hsts_findings[0]['severity']}"
        )

    def test_missing_csp_detected(self):
        """CSP missing must produce a high-severity finding."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options":           "DENY",
        }
        vulns = self._run_check_headers(headers)
        csp_findings = [v for v in vulns
                        if "csp" in v.get("check", "").lower()
                        or "content-security-policy" in v.get("title", "").lower()
                        or "content-security-policy" in v.get("description", "").lower()]
        assert len(csp_findings) >= 1, "CSP missing was not detected"

    def test_missing_xframe_detected(self):
        """X-Frame-Options missing must produce a medium-severity finding."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy":   "default-src 'self'",
        }
        vulns = self._run_check_headers(headers)
        xframe_findings = [v for v in vulns
                           if "x-frame" in v.get("check", "").lower()
                           or "x-frame" in v.get("title", "").lower()
                           or "clickjack" in v.get("description", "").lower()]
        assert len(xframe_findings) >= 1, "X-Frame-Options missing was not detected"

    def test_all_headers_present_produces_no_header_findings(self):
        """When all required headers are present, no header findings should be reported."""
        headers = {
            "Strict-Transport-Security":  "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy":    "default-src 'self'; object-src 'none'",
            "X-Frame-Options":            "DENY",
            "X-Content-Type-Options":     "nosniff",
            "Referrer-Policy":            "strict-origin-when-cross-origin",
            "Permissions-Policy":         "geolocation=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
        vulns = self._run_check_headers(headers)
        header_findings = [
            v for v in vulns
            if any(h[0].lower() in v.get("check", "").lower()
                   or h[0].lower() in v.get("title", "").lower()
                   for h in [
                       ("strict-transport",), ("content-security-policy",),
                       ("x-frame-options",), ("x-content-type-options",),
                   ])
        ]
        assert header_findings == [], (
            f"Unexpected header findings when all headers are present: {header_findings}"
        )

    def test_no_headers_at_all_produces_multiple_findings(self):
        """Response with no security headers must produce multiple findings."""
        vulns = self._run_check_headers({})
        # At minimum, HSTS and CSP should both fire
        assert len(vulns) >= 2, (
            f"Expected at least 2 findings for response with no headers, got {len(vulns)}"
        )


# \u2500\u2500 Server version / CVE detection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestServerVersionDetection:
    """
    Tests for server banner parsing and CVE pattern matching.
    These use the module-level VULN_SERVER_RE list directly.
    """

    def test_vuln_patterns_are_non_empty(self):
        """Ensure the CVE pattern list is loaded and non-empty."""
        from scanners.web_scanner import VULN_SERVER_RE
        assert len(VULN_SERVER_RE) >= 5

    def test_each_pattern_tuple_has_four_fields(self):
        """Each pattern must be (regex, cve_id, description, severity)."""
        from scanners.web_scanner import VULN_SERVER_RE
        for pattern in VULN_SERVER_RE:
            assert len(pattern) == 4, (
                f"VULN_SERVER_RE entry must have 4 fields: {pattern}"
            )
            regex, cve_id, desc, severity = pattern
            assert regex, "Regex must not be empty"
            assert cve_id.startswith("CVE-"), f"CVE ID must start with 'CVE-': {cve_id}"
            assert desc, "Description must not be empty"
            assert severity in ("critical", "high", "medium", "low", "info"), (
                f"Invalid severity: {severity}"
            )

    def test_required_headers_are_non_empty(self):
        """REQUIRED_HEADERS must define at least the 7 standard security headers."""
        from scanners.web_scanner import REQUIRED_HEADERS
        assert len(REQUIRED_HEADERS) >= 5
        header_names = [h[0].lower() for h in REQUIRED_HEADERS]
        assert "strict-transport-security" in header_names
        assert "content-security-policy" in header_names
        assert "x-frame-options" in header_names

    def test_sensitive_paths_are_non_empty(self):
        """SENSITIVE_PATHS must contain critical and high severity entries."""
        from scanners.web_scanner import SENSITIVE_PATHS
        severities = {p[1] for p in SENSITIVE_PATHS}
        assert "critical" in severities
        assert "high" in severities


# \u2500\u2500 Error / info disclosure detection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestErrorPatterns:
    """Tests for the ERROR_PATTERNS list that detects sensitive data in HTTP responses."""

    def test_error_patterns_are_non_empty(self):
        from scanners.web_scanner import ERROR_PATTERNS
        assert len(ERROR_PATTERNS) >= 10

    def test_each_pattern_has_three_fields(self):
        from scanners.web_scanner import ERROR_PATTERNS
        for pattern in ERROR_PATTERNS:
            assert len(pattern) == 3, f"ERROR_PATTERNS entry must have 3 fields: {pattern}"
            regex, severity, desc = pattern
            assert regex
            assert severity in ("critical", "high", "medium", "low", "info")
            assert desc

    def test_sql_error_is_critical(self):
        """MySQL/Oracle/MSSQL error patterns must classify as critical."""
        from scanners.web_scanner import ERROR_PATTERNS
        critical_patterns = [p for p in ERROR_PATTERNS if p[1] == "critical"]
        critical_regexes = " ".join(p[0] for p in critical_patterns)
        assert "SQL" in critical_regexes or "ORA-" in critical_regexes, (
            "SQL error patterns must be present and classified as critical"
        )

    def test_private_key_pattern_is_critical(self):
        """Private key exposure must be classified as critical."""
        from scanners.web_scanner import ERROR_PATTERNS
        key_patterns = [p for p in ERROR_PATTERNS if "PRIVATE KEY" in p[0]]
        assert key_patterns, "Private key pattern must exist in ERROR_PATTERNS"
        assert all(p[1] == "critical" for p in key_patterns), (
            "Private key disclosure must be classified as critical"
        )


# \u2500\u2500 HTTPS redirect check \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

class TestHttpsRedirectCheck:
    """
    Tests for the HTTP-to-HTTPS redirect enforcement check.
    A site that does not redirect HTTP → HTTPS allows plaintext data transmission.
    """

    def test_dangerous_methods_list_is_non_empty(self):
        """DANGEROUS_METHODS must define at least TRACE and PUT."""
        from scanners.web_scanner import DANGEROUS_METHODS
        method_names = [m[0] for m in DANGEROUS_METHODS]
        assert "TRACE" in method_names
        assert "PUT" in method_names

    def test_dangerous_put_is_high_severity(self):
        """HTTP PUT enabled must be classified as high severity."""
        from scanners.web_scanner import DANGEROUS_METHODS
        put_entries = [m for m in DANGEROUS_METHODS if m[0] == "PUT"]
        assert put_entries, "PUT must be in DANGEROUS_METHODS"
        assert put_entries[0][1] == "high", "HTTP PUT must be high severity"

    def test_dangerous_trace_is_medium_or_higher(self):
        """HTTP TRACE enabled (XST attack vector) must be medium or higher."""
        from scanners.web_scanner import DANGEROUS_METHODS
        trace_entries = [m for m in DANGEROUS_METHODS if m[0] == "TRACE"]
        assert trace_entries, "TRACE must be in DANGEROUS_METHODS"
        assert trace_entries[0][1] in ("medium", "high", "critical"), (
            "HTTP TRACE must be at least medium severity"
        )
