"""SecuraX — Deep SSL/TLS Scanner using SSLyze (with graceful fallback).

P1.4 Implementation:
  • Checks if sslyze is available in the environment.
  • Performs deep vulnerability checks:
      - Heartbleed (CVE-2014-0160)
      - ROBOT (Return Of Bleichenbacher's Oracle Threat)
      - OpenSSL CCS Injection (CVE-2014-0224)
      - TLS Compression / CRIME (CVE-2012-4929)
      - Insecure Session Renegotiation
  • Performs full cipher suite enumeration across SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3.
  • Graceful fallback: If sslyze is not installed, returns safely without failing.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Check sslyze availability dynamically
_SSLYZE_AVAILABLE = False
try:
    import sslyze  # noqa: F401
    _SSLYZE_AVAILABLE = True
except ImportError:
    _SSLYZE_AVAILABLE = False


def is_sslyze_available() -> bool:
    """Return True if sslyze library is available for deep scanning."""
    return _SSLYZE_AVAILABLE


def run_sslyze_scan(host: str, port: int = 443) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run SSLyze deep scan against the target host:port.

    Returns:
        tuple (vulnerabilities: list[dict], meta: dict)
        If sslyze is unavailable or scanning fails, returns empty list with metadata
        so standard library ssl_scanner can proceed uninterrupted.
    """
    if not is_sslyze_available():
        return [], {
            "sslyze_available": False,
            "reason": "sslyze package is not installed on the system",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    vulns: list[dict[str, Any]] = []
    meta: dict[str, Any] = {
        "sslyze_available": True,
        "target": f"{host}:{port}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ciphers": {},
        "vulnerabilities_checked": [
            "heartbleed",
            "robot",
            "openssl_ccs",
            "tls_compression",
            "session_renegotiation",
        ],
    }

    try:
        from sslyze import (
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommandsRepository,
            Scanner,
        )

        server_location = ServerNetworkLocation(hostname=host, port=port)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommandsRepository.HEARTBLEED,
                ScanCommandsRepository.ROBOT,
                ScanCommandsRepository.OPENSSL_CCS_INJECTION,
                ScanCommandsRepository.TLS_COMPRESSION,
                ScanCommandsRepository.SESSION_RENEGOTIATION,
                ScanCommandsRepository.SSL_2_0_CIPHER_SUITES,
                ScanCommandsRepository.SSL_3_0_CIPHER_SUITES,
                ScanCommandsRepository.TLS_1_0_CIPHER_SUITES,
                ScanCommandsRepository.TLS_1_1_CIPHER_SUITES,
                ScanCommandsRepository.TLS_1_2_CIPHER_SUITES,
                ScanCommandsRepository.TLS_1_3_CIPHER_SUITES,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])
        for server_scan_result in scanner.get_results():
            # 1. Heartbleed check
            hb_result = server_scan_result.scan_result.heartbleed
            if hb_result and hb_result.result and hb_result.result.is_vulnerable_to_heartbleed:
                vulns.append({
                    "check": "sslyze-heartbleed",
                    "title": "[SSLyze] Heartbleed OpenSSL Memory Disclosure (CVE-2014-0160)",
                    "severity": "critical",
                    "description": "The server is vulnerable to Heartbleed, allowing unauthenticated attackers to read server memory.",
                    "evidence": f"{host}:{port} returned memory heartbeat response",
                    "remediation": "Upgrade OpenSSL to a patched version immediately.",
                    "cve_ids": ["CVE-2014-0160"],
                })

            # 2. ROBOT check
            robot_result = server_scan_result.scan_result.robot
            if robot_result and robot_result.result:
                robot_enum = str(robot_result.result.robot_result_enum).lower()
                if "vulnerable" in robot_enum:
                    vulns.append({
                        "check": "sslyze-robot",
                        "title": "[SSLyze] ROBOT Attack Vulnerability (Bleichenbacher RSA Oracle)",
                        "severity": "high",
                        "description": "The server is vulnerable to the ROBOT attack, which allows decryption of RSA TLS ciphertexts.",
                        "evidence": f"ROBOT result: {robot_result.result.robot_result_enum}",
                        "remediation": "Disable RSA key exchange cipher suites; prioritize ECDHE.",
                        "cve_ids": ["CVE-2017-13099"],
                    })

            # 3. OpenSSL CCS Injection
            ccs_result = server_scan_result.scan_result.openssl_ccs_injection
            if ccs_result and ccs_result.result and ccs_result.result.is_vulnerable_to_ccs_injection:
                vulns.append({
                    "check": "sslyze-openssl-ccs",
                    "title": "[SSLyze] OpenSSL CCS Injection (CVE-2014-0224)",
                    "severity": "high",
                    "description": "The server allows an attacker to bypass TLS handshake authentication.",
                    "evidence": f"{host}:{port} vulnerable to early CCS injection",
                    "remediation": "Update OpenSSL to the latest stable release.",
                    "cve_ids": ["CVE-2014-0224"],
                })

            # 4. TLS Compression (CRIME)
            comp_result = server_scan_result.scan_result.tls_compression
            if comp_result and comp_result.result and comp_result.result.supports_compression:
                vulns.append({
                    "check": "sslyze-tls-compression",
                    "title": "[SSLyze] TLS Compression Enabled (CRIME Attack Vector)",
                    "severity": "medium",
                    "description": "TLS compression is enabled on the server, making session cookies vulnerable to CRIME attack.",
                    "evidence": "TLS compression is supported",
                    "remediation": "Disable TLS-level compression on the web server.",
                    "cve_ids": ["CVE-2012-4929"],
                })

            # 5. Insecure Session Renegotiation
            reneg_result = server_scan_result.scan_result.session_renegotiation
            if reneg_result and reneg_result.result:
                if reneg_result.result.is_vulnerable_to_client_renegotiation_dos:
                    vulns.append({
                        "check": "sslyze-renegotiation-dos",
                        "title": "[SSLyze] Insecure Client-Initiated TLS Renegotiation (DoS)",
                        "severity": "medium",
                        "description": "Server permits client-initiated session renegotiation, exposing it to CPU-exhaustion DoS attacks.",
                        "evidence": "Client-initiated renegotiation accepted",
                        "remediation": "Disable client-initiated TLS renegotiation in web server configuration.",
                        "cve_ids": [],
                    })

            # Cipher enumeration summary
            ciphers_info: dict[str, list[str]] = {}
            for ver_name, attr in [
                ("ssl_2_0", "ssl_2_0_cipher_suites"),
                ("ssl_3_0", "ssl_3_0_cipher_suites"),
                ("tls_1_0", "tls_1_0_cipher_suites"),
                ("tls_1_1", "tls_1_1_cipher_suites"),
                ("tls_1_2", "tls_1_2_cipher_suites"),
                ("tls_1_3", "tls_1_3_cipher_suites"),
            ]:
                suite_res = getattr(server_scan_result.scan_result, attr, None)
                if suite_res and suite_res.result:
                    accepted = [c.cipher_suite.name for c in getattr(suite_res.result, "accepted_cipher_suites", [])]
                    if accepted:
                        ciphers_info[ver_name] = accepted
                        if ver_name in ("ssl_2_0", "ssl_3_0"):
                            vulns.append({
                                "check": f"sslyze-{ver_name}-enabled",
                                "title": f"[SSLyze] Insecure Protocol {ver_name.upper().replace('_', ' ')} Accepted",
                                "severity": "critical" if ver_name == "ssl_2_0" else "high",
                                "description": f"The server negotiates obsolete and insecure protocol {ver_name.upper()}.",
                                "evidence": f"Accepted ciphers: {', '.join(accepted[:5])}",
                                "remediation": f"Disable {ver_name.upper()} in server TLS configuration.",
                                "cve_ids": [],
                            })

            meta["ciphers"] = ciphers_info

    except Exception as exc:
        logger.warning("sslyze_scan error for %s:%d — %s", host, port, exc)
        meta["error"] = str(exc)

    return vulns, meta
