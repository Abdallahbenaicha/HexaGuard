"""Unit and integration tests for Bug Bounty Roadmap Phase P1:
  • P1.1: Manual Engine & Rate Control Panel (selective engine execution & rate limits)
  • P1.2: Wildcard Reconnaissance Pipeline (crt.sh + policy gate enforcement)
  • P1.3: Custom Researcher Attribution Header (strictly scoped to bounty scans)
  • P1.4: Deep TLS Scanner (SSLyze with graceful fallback)

Includes explicit security verification function:
  test_wildcard_recon_respects_policy_gate
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest

os.environ["SECURAX_TESTING"] = "1"
os.environ["ENABLE_LIVE_BOUNTY_SCANNING"] = "true"

from app import create_app
from blueprints.bounty import _bounty_engine_params, _enforce_bounty_policy_gate
from database import init_db
from scanners.dast_scanner import DASTConfig, run_dast_scan
from scanners.ssl_scanner import run_ssl_scan
from scanners.sslyze_scanner import is_sslyze_available, run_sslyze_scan


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        init_db()
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["user_id"] = 1
            sess["username"] = "bounty_hunter"
            sess["role"] = "admin"
        yield c


# ════════════════════════════════════════════════════════════════════════════
# P1.2: Wildcard Reconnaissance & Policy Gate Enforcement
# ════════════════════════════════════════════════════════════════════════════

def test_wildcard_recon_respects_policy_gate(client):
    """CRITICAL SECURITY TEST (DoD):

    Verify that /api/bounty/recon/subdomains enforces _enforce_bounty_policy_gate:
    1. Active probing (probe_alive=True) on an unacknowledged RESTRICTED target
       MUST be BLOCKED with HTTP 403 (POLICY_GATE_BLOCKED). Zero active probes sent.
    2. Passive discovery (probe_alive=False) on the same target is allowed because
       it queries public Certificate Transparency logs (crt.sh) only.
    3. Active probing with acknowledged=True successfully passes the gate.
    """
    restricted_bounty_ctx = {
        "asset": "*.restricted-corp.com",
        "platform": "hackerone",
        "program_handle": "restricted-corp",
        "scan_policy": {
            "status": "RESTRICTED",
            "confidence": 85,
            "signals": ["- Explicit restriction: 'no automated scanning'"],
        },
        "acknowledged": False,
    }

    # 1. Unacknowledged + probe_alive=True -> MUST FAIL WITH 403 POLICY_GATE_BLOCKED
    with patch("blueprints.bounty._probe_single_subdomain") as mock_probe:
        res = client.post(
            "/api/bounty/recon/subdomains",
            json={
                "domain": "*.restricted-corp.com",
                "bounty_context": restricted_bounty_ctx,
                "probe_alive": True,
            },
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data.get("code") == "POLICY_GATE_BLOCKED"
        # Verify ZERO active probe calls were dispatched
        assert mock_probe.call_count == 0

    # 2. Unacknowledged + probe_alive=False (Passive mode) -> Allowed
    with patch("blueprints.bounty._fetch_crtsh_subdomains", return_value=["app.restricted-corp.com", "api.restricted-corp.com"]):
        with patch("blueprints.bounty._probe_single_subdomain") as mock_probe:
            res = client.post(
                "/api/bounty/recon/subdomains",
                json={
                    "domain": "*.restricted-corp.com",
                    "bounty_context": restricted_bounty_ctx,
                    "probe_alive": False,
                },
            )
            assert res.status_code == 200
            data = res.get_json()
            assert data["total_discovered"] == 2
            assert data["probe_alive"] is False
            assert all(r["status"] == "unprobed" for r in data["results"])
            assert mock_probe.call_count == 0

    # 3. Acknowledged=True + probe_alive=True -> Allowed and probes dispatched
    acknowledged_bounty_ctx = dict(restricted_bounty_ctx)
    acknowledged_bounty_ctx["acknowledged"] = True

    mock_probe_result = {
        "subdomain": "api.restricted-corp.com",
        "alive": True,
        "status_code": 200,
        "server": "nginx",
        "ip": "93.184.216.34",
    }

    with patch("blueprints.bounty._fetch_crtsh_subdomains", return_value=["api.restricted-corp.com"]):
        with patch("blueprints.bounty._probe_single_subdomain", return_value=mock_probe_result) as mock_probe:
            res = client.post(
                "/api/bounty/recon/subdomains",
                json={
                    "domain": "*.restricted-corp.com",
                    "bounty_context": acknowledged_bounty_ctx,
                    "probe_alive": True,
                },
            )
            assert res.status_code == 200
            data = res.get_json()
            assert data["probe_alive"] is True
            assert len(data["results"]) == 1
            assert data["results"][0]["alive"] is True
            assert mock_probe.call_count == 1


def test_wildcard_recon_feature_flag_isolation(client):
    """When ENABLE_LIVE_BOUNTY_SCANNING is false, recon returns 403 or is inaccessible."""
    with patch.dict(os.environ, {"ENABLE_LIVE_BOUNTY_SCANNING": "false"}):
        res = client.post(
            "/api/bounty/recon/subdomains",
            json={
                "domain": "*.example.com",
                "bounty_context": {"asset": "*.example.com"},
                "probe_alive": True,
            },
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data.get("code") == "BOUNTY_SCANNING_DISABLED"


# ════════════════════════════════════════════════════════════════════════════
# P1.1: Engine Selection & Rate Limiting
# ════════════════════════════════════════════════════════════════════════════

def test_dast_engine_selective_execution():
    """Verify DASTConfig.enabled_engines filters submitted engines."""
    # Test 1: Only nuclei enabled -> ZAP and Nikto must NOT be called
    cfg = DASTConfig(
        enabled_engines=["nuclei"],
        rate_limit=10,
        threads=2,
    )
    with patch("scanners.dast_scanner._run_nuclei_scan", return_value=([], None)) as mock_nuclei, \
         patch("scanners.dast_scanner._run_zap_scan") as mock_zap, \
         patch("scanners.dast_scanner._run_nikto_scan") as mock_nikto, \
         patch("scanners.dast_scanner._check_ssrf", return_value=(True, None)):

        res = run_dast_scan("http://example.com", config=cfg)
        assert mock_nuclei.called
        assert not mock_zap.called
        assert not mock_nikto.called
        assert res["meta"]["errors"]["zap"] == "ZAP not enabled"
        assert res["meta"]["errors"]["nikto"] == "Nikto not enabled"


def test_dast_engine_selection_via_bridge(client):
    """Verify scan_dast_bridge passes enabled_engines and rate limits."""
    payload = {
        "target": "http://scanme.nmap.org",
        "enabled_engines": ["nuclei"],
        "rate_limit": 5,
        "threads": 1,
    }
    with patch("blueprints.scans.run_dast_scan", return_value={"scan_type": "dast", "vulnerabilities": []}) as mock_scan:
        with patch("blueprints.scans._check_target_lock", return_value=(True, None)):
            res = client.post("/scan_dast", json=payload)
            assert res.status_code == 200
            called_cfg = mock_scan.call_args[1]["config"]
            assert called_cfg.enabled_engines == ["nuclei"]
            assert called_cfg.rate_limit == 5
            assert called_cfg.threads == 1


# ════════════════════════════════════════════════════════════════════════════
# P1.3: Custom Researcher Attribution Header Scoping
# ════════════════════════════════════════════════════════════════════════════

def test_bounty_attribution_header_scoped_strictly_to_bounty(client):
    """Attribution header MUST be present during bounty scans, but ABSENT in regular pentest scans."""
    # Scenario A: Standard scan WITHOUT bounty_context (e.g. pentest)
    normal_payload = {
        "url": "http://scanme.nmap.org",
        "auth_config": {"cookie": "session=abc"},
    }
    with patch("blueprints.scans.run_web_scan", return_value={"scan_type": "web", "vulnerabilities": [], "meta": {}}) as mock_web:
        with patch("blueprints.scans._check_target_lock", return_value=(True, None)):
            res = client.post("/scan_url", json=normal_payload)
            assert res.status_code == 200
            headers_sent = mock_web.call_args[1].get("extra_headers") or {}
            # Verify no bounty attribution header leaked in standard pentest scan
            assert "X-Bug-Bounty-Hacker" not in headers_sent
            assert "User-Agent" not in headers_sent

    # Scenario B: Scan WITH bounty_context
    bounty_payload = {
        "url": "http://scanme.nmap.org",
        "bounty_context": {
            "asset": "scanme.nmap.org",
            "platform": "hackerone",
            "program_handle": "test-program",
            "scan_policy": {"status": "ALLOWED", "confidence": 90, "signals": []},
            "acknowledged": True,
        },
    }
    with patch("blueprints.scans.run_web_scan", return_value={"scan_type": "web", "vulnerabilities": [], "meta": {}}) as mock_web:
        with patch("blueprints.scans._check_target_lock", return_value=(True, None)):
            res = client.post("/scan_url", json=bounty_payload)
            assert res.status_code == 200
            headers_sent = mock_web.call_args[1].get("extra_headers") or {}
            # Verify bounty attribution header is properly injected
            assert headers_sent.get("X-Bug-Bounty-Hacker") == "admin"
            assert "SecuraX-Bounty-Scanner" in headers_sent.get("User-Agent", "")


# ════════════════════════════════════════════════════════════════════════════
# P1.4: Deep TLS Scanner (SSLyze with Graceful Fallback)
# ════════════════════════════════════════════════════════════════════════════

def test_sslyze_scanner_graceful_fallback():
    """When sslyze is missing or unavailable, scanning must complete gracefully."""
    vulns, meta = run_sslyze_scan("example.com", 443)
    assert isinstance(vulns, list)
    assert isinstance(meta, dict)
    assert meta.get("sslyze_available") is False or "target" in meta


def test_ssl_scanner_includes_sslyze_meta():
    """run_ssl_scan includes sslyze metadata and does not crash."""
    with patch("scanners.ssl_scanner._get_cert_info", return_value={"cert": {}, "tls_ok": True, "version": "TLSv1.3", "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)}), \
         patch("scanners.ssl_scanner._check_deprecated_proto", return_value=False), \
         patch("scanners.ssl_scanner._check_hsts", return_value=(False, 0)), \
         patch("scanners.ssl_scanner._check_https_redirect", return_value=True):

        res = run_ssl_scan("example.com")
        assert "meta" in res
        assert "sslyze" in res["meta"]
        assert "tools" in res["meta"]

