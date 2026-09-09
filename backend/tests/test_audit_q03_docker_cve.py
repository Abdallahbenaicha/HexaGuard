"""Unit tests for Q-03: Container image CVE scanning with Trivy, Grype, and Fallback engine."""

import json
from unittest.mock import MagicMock, patch

import pytest
from scanners.docker_scanner import (
    scan_docker_image,
    _scan_image_with_trivy,
    _scan_image_with_grype,
    _scan_image_fallback,
)


class TestDockerImageCveScanner:
    def test_empty_image_name_raises_value_error(self):
        with pytest.raises(ValueError):
            scan_docker_image("")

    def test_fallback_known_vulnerable_node_image(self):
        result = scan_docker_image("node:14")
        assert result["scan_type"] == "docker_image_cve"
        assert result["target"] == "node:14"
        assert result["counts"]["high"] >= 1
        cve_ids = [v["cve_id"] for v in result["vulnerabilities"] if "cve_id" in v]
        assert "CVE-2021-22918" in cve_ids
        assert "CVE-2020-8203" in cve_ids

    def test_fallback_known_vulnerable_python_image(self):
        result = scan_docker_image("python:3.7")
        assert result["target"] == "python:3.7"
        assert result["counts"]["critical"] >= 1
        cve_ids = [v["cve_id"] for v in result["vulnerabilities"] if "cve_id" in v]
        assert "CVE-2021-3177" in cve_ids

    def test_unpinned_image_tag_warning(self):
        result = scan_docker_image("custom-service:latest")
        assert any("Unpinned Image Tag" in v["title"] for v in result["vulnerabilities"])
        assert result["counts"]["medium"] >= 1

    def test_trivy_cli_parsing_integration(self):
        mock_trivy_json = json.dumps({
            "Results": [
                {
                    "Target": "my-app:v1 (debian 11.2)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "curl",
                            "InstalledVersion": "7.74.0-1.3+deb11u1",
                            "FixedVersion": "7.74.0-1.3+deb11u7",
                            "Severity": "CRITICAL",
                            "Title": "curl integer overflow",
                            "Description": "Critical curl flaw allows arbitrary code execution",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-12345",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-67890",
                            "PkgName": "libssl1.1",
                            "InstalledVersion": "1.1.1n-0+deb11u3",
                            "FixedVersion": "1.1.1n-0+deb11u5",
                            "Severity": "HIGH",
                            "Title": "OpenSSL memory leak",
                            "Description": "High severity OpenSSL memory leakage",
                        }
                    ]
                }
            ]
        })
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_trivy_json

        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scan_docker_image("my-app:v1", preferred_engine="trivy")

            assert result["engine"] == "trivy"
            assert result["counts"]["critical"] == 1
            assert result["counts"]["high"] == 1
            cve_ids = [v["cve_id"] for v in result["vulnerabilities"]]
            assert "CVE-2023-12345" in cve_ids
            assert "CVE-2023-67890" in cve_ids

    def test_grype_cli_parsing_integration(self):
        mock_grype_json = json.dumps({
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2022-9999",
                        "severity": "High",
                        "description": "Buffer overflow in zlib",
                        "fix": {"versions": ["1.2.12"]},
                    },
                    "artifact": {
                        "name": "zlib1g",
                        "version": "1.2.11.dfsg-2+deb11u1",
                    }
                }
            ]
        })
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_grype_json

        with patch("shutil.which", return_value="/usr/local/bin/grype"), \
             patch("subprocess.run", return_value=mock_proc):
            result = scan_docker_image("custom-backend:prod", preferred_engine="grype")

            assert result["engine"] == "grype"
            assert result["counts"]["high"] == 1
            assert result["vulnerabilities"][0]["cve_id"] == "CVE-2022-9999"
            assert result["vulnerabilities"][0]["pkg_name"] == "zlib1g"
            assert result["vulnerabilities"][0]["fixed_version"] == "1.2.12"
