"""Unit tests for Q-04: EPSS score integration in runtime risk engine."""

from unittest.mock import MagicMock, patch

import pytest
from risk_engine import (
    calculate_risk_v2,
    get_epss_score_for_cve,
    get_epss_scores,
    _fetch_epss_scores_batch,
    _EPSS_CACHE,
    _EPSS_CACHE_LOCK,
)


class TestRiskEngineEpssIntegration:
    def setup_method(self):
        with _EPSS_CACHE_LOCK:
            _EPSS_CACHE.clear()

    def test_fetch_epss_scores_parses_api_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.97512", "percentile": "0.99980"},
                {"cve": "CVE-2023-12345", "epss": "0.45000", "percentile": "0.91000"},
            ]
        }

        with patch("requests.get", return_value=mock_resp):
            scores = _fetch_epss_scores_batch(["CVE-2021-44228", "CVE-2023-12345"])
            assert scores["CVE-2021-44228"] == pytest.approx(0.97512)
            assert scores["CVE-2023-12345"] == pytest.approx(0.45)
            assert get_epss_score_for_cve("CVE-2021-44228") == pytest.approx(0.97512)

    def test_fetch_epss_handles_api_failure_gracefully(self):
        with patch("requests.get", side_effect=Exception("API connection timeout")):
            scores = _fetch_epss_scores_batch(["CVE-2024-9999"])
            assert scores == {}
            assert get_epss_score_for_cve("CVE-2024-9999") == 0.0

    def test_calculate_risk_v2_elevates_temporal_score_with_high_epss(self):
        cve = "CVE-2021-44228"
        finding = {
            "severity": "high",
            "check": "log4j",
            "title": "Log4Shell RCE",
            "description": "Log4j JNDI injection",
            "cve_ids": [cve],
        }

        # Baseline: without EPSS boost
        with patch("risk_engine._fetch_epss_scores_batch", return_value={cve: 0.01}), \
             patch("risk_engine.get_kev_set", return_value=set()):
            base_risk = calculate_risk_v2({"vulnerabilities": [finding]}, criticality=0.5)

        # High EPSS (0.95 -> imminent exploitation risk)
        with patch("risk_engine._fetch_epss_scores_batch", return_value={cve: 0.95}), \
             patch("risk_engine.get_kev_set", return_value=set()):
            elevated_risk = calculate_risk_v2({"vulnerabilities": [finding]}, criticality=0.5)

        assert elevated_risk.max_epss == 0.95
        assert elevated_risk.epss_scores[cve] == 0.95
        # Temporal score must be noticeably higher with 95th+ percentile EPSS
        assert elevated_risk.temporal_score > base_risk.temporal_score
        assert elevated_risk.final_score >= base_risk.final_score

    def test_calculate_risk_v2_populates_breakdown_metadata(self):
        cve1 = "CVE-2022-22965"
        cve2 = "CVE-2023-44487"
        findings = [
            {"severity": "medium", "cve_id": cve1, "title": "Spring4Shell"},
            {"severity": "low", "cve_ids": [cve2], "title": "HTTP/2 Rapid Reset"},
        ]

        mock_map = {cve1: 0.65, cve2: 0.30}
        with patch("risk_engine._fetch_epss_scores_batch", return_value=mock_map):
            risk = calculate_risk_v2({"vulnerabilities": findings})

        assert risk.max_epss == 0.65
        assert risk.epss_scores == mock_map
