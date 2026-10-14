"""
test_dast_wordpress_audit.py
=============================
Hermetic tests verifying:
  1. DAST_ALLOW_INTERNAL is disabled by default, and blocks internal/private targets.
  2. When DAST_ALLOW_INTERNAL=1 is set, internal targets are allowed through SSRF guard.
  3. DAST returns graceful INFO finding when external binaries (Nikto/ZAP/Nuclei) are missing.
  4. WordPress scanner positive detection on synthetic HTML containing wp-content and WordPress 5.0 meta generator.
  5. WordPress scanner negative detection on plain HTML.
"""

import os
from unittest.mock import patch, MagicMock
import pytest

from scanners.dast_scanner import run_dast_scan, DASTConfig
from scanners.wordpress_scanner import run_wordpress_scan, _detect_wordpress


def test_dast_allow_internal_disabled_by_default(monkeypatch):
    """DAST_ALLOW_INTERNAL must default to 0 / disabled, blocking private targets."""
    monkeypatch.delenv("DAST_ALLOW_INTERNAL", raising=False)
    with pytest.raises(ValueError, match="resolves to private/reserved address"):
        run_dast_scan("http://127.0.0.1:8080")


def test_dast_allow_internal_lab_mode(monkeypatch):
    """When DAST_ALLOW_INTERNAL=1 is set, private targets pass SSRF guard."""
    monkeypatch.setenv("DAST_ALLOW_INTERNAL", "1")
    # All engines will fail/be unavailable without binaries, but SSRF guard passes
    res = run_dast_scan("http://127.0.0.1:8080")
    assert res["scan_type"] == "dast"
    assert res["target"] == "http://127.0.0.1:8080"
    # Proves graceful fallback when binaries are missing
    assert any("unavailable" in v["title"].lower() for v in res["vulnerabilities"])


def test_wordpress_positive_detection_on_synthetic_html():
    """Positive test: detects WordPress on synthetic HTML containing wp-content and generator meta."""
    mock_resp = MagicMock()
    mock_resp.text = """
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="generator" content="WordPress 5.0" />
        <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />
      </head>
      <body>
        <h1>SecuraX WordPress Lab</h1>
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
      </body>
    </html>
    """
    mock_resp.status_code = 200

    with patch("scanners.wordpress_scanner._get", return_value=mock_resp):
        is_wp, ver = _detect_wordpress("https://wp-lab.example")
        assert is_wp is True, "Expected WordPress to be positively detected"
        assert ver == "5.0", f"Expected version 5.0, got {ver}"

        # Run full scan with mocked HTTP requests
        res = run_wordpress_scan("https://wp-lab.example")
        assert res["scan_type"] == "wordpress"
        # Should flag outdated EOL version
        vuln_titles = [v["title"] for v in res["vulnerabilities"]]
        assert any("outdated" in t.lower() or "5.0" in t for t in vuln_titles)


def test_wordpress_negative_detection_on_non_wp_html():
    """Negative test: does not detect WordPress on standard non-WordPress site."""
    mock_resp = MagicMock()
    mock_resp.text = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>Static Documentation</title>
      </head>
      <body>
        <h1>Welcome</h1>
      </body>
    </html>
    """
    mock_resp.status_code = 200

    with patch("scanners.wordpress_scanner._get", return_value=mock_resp):
        is_wp, ver = _detect_wordpress("https://non-wp.example")
        assert is_wp is False
        assert ver is None
