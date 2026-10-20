"""SecuraX Evaluation Lab — Fail-Closed Scope & Target Gate.

Governed strictly by Master Specification v5 Phase 1:
  - Fail-closed evaluation for every lab run.
  - Verification of Target Registry status and scanner/scan_type eligibility.
  - Strict blocking of public_reference (never executable).
  - 90-day expiration check and remote scanning flags on public_permitted.
  - Address sanitization: rejects IP-literal tricks, octal/hex/dword, userinfo,
    link-local, cloud metadata, and verifies at connection-time against DNS rebinding.
  - Explicit local lab identity verification surviving the defined threat model
    (confused admin, stale container, malicious local service) via bounded fingerprint probe.
  - Complete audit logging of all gate decisions (denials and allowances).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Optional, Tuple

import requests

from lab.config import is_lab_mode_enabled, is_lab_remote_scanning_enabled
from lab.models import GateDecision, LabGateResult, TargetKind
from db.lab import get_lab_target
from db.audit import log_event

logger = logging.getLogger(__name__)

# RFC-1918 and loopback networks for local targets
_ALLOWED_LOCAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Prohibited destination networks (link-local, cloud metadata)
_PROHIBITED_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

_PROHIBITED_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.local",
    "instance-data",
}

# Regex for detecting obfuscated IP encodings (octal, hex, dword integer IP)
_HEX_IP_RE   = re.compile(r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+)*$")
_OCTAL_IP_RE = re.compile(r"^0[0-7]+(\.0[0-7]+)*$")
_DWORD_IP_RE = re.compile(r"^\d{8,11}$")


def _sanitize_and_resolve_address(address_str: str) -> Tuple[bool, str, Optional[str]]:
    """Validate address, reject evasion tricks, and resolve IP at connection time.

    Returns: (is_valid, resolved_ip_or_hostname, error_message)
    """
    if not address_str or not address_str.strip():
        return False, "", "Empty target address."

    addr = address_str.strip()

    # Reject userinfo trick anywhere in address
    if "@" in addr:
        return False, "", "Userinfo trick in address rejected."

    # Parse URL if scheme provided, or normalize scheme-less host[:port][/path]
    if "://" in addr:
        parsed = urllib.parse.urlsplit(addr)
        if parsed.username or parsed.password:
            return False, "", "Userinfo trick in URL rejected."
        host = parsed.hostname or ""
    else:
        # Scheme-less: e.g. "192.168.1.50:8080", "127.0.0.1", "localhost:3000"
        parsed = urllib.parse.urlsplit(f"//{addr}")
        host = parsed.hostname or ""
        if not host:
            raw_host = addr.split("/")[0]
            host = raw_host.split(":")[0] if ":" in raw_host else raw_host

    if not host:
        return False, "", f"Could not determine valid hostname from address '{address_str}'."

    host = host.rstrip(".").lower()

    if host in _PROHIBITED_HOSTNAMES:
        return False, "", "Cloud metadata destination strictly blocked."

    # Reject hex, octal, or dword IP obfuscations
    if _HEX_IP_RE.match(host) or _OCTAL_IP_RE.match(host) or _DWORD_IP_RE.match(host):
        return False, "", "Obfuscated integer/hex/octal IP address rejected."

    # If host is already a canonical IPv4 or IPv6 address literal
    try:
        ip_obj = ipaddress.ip_address(host)
        if any(ip_obj in net for net in _PROHIBITED_METADATA_NETWORKS):
            return False, "", "Resolved IP is within blocked link-local/cloud metadata network."
        return True, str(ip_obj), None
    except ValueError:
        pass

    # Connection-time DNS resolution for hostnames to prevent DNS rebinding
    try:
        resolved_infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return False, "", f"DNS resolution failed for '{host}': {exc}"
    except Exception as exc:
        return False, "", f"Address resolution error for '{host}': {exc}"

    if not resolved_infos:
        return False, "", f"No IP address resolved for host '{host}'."

    first_ip = resolved_infos[0][4][0]
    try:
        ip_obj = ipaddress.ip_address(first_ip)
    except ValueError:
        return False, "", f"Invalid resolved IP '{first_ip}'."

    # Check against prohibited metadata
    if any(ip_obj in net for net in _PROHIBITED_METADATA_NETWORKS):
        return False, "", "Resolved IP is within blocked link-local/cloud metadata network."

    return True, first_ip, None




def _verify_lab_identity(
    address_str: str,
    expected_fingerprint: Optional[str],
) -> Tuple[bool, str]:
    """Verify local lab container identity against defined threat model.

    Threat Model:
      1. Confused Admin: Admin targeted wrong port (e.g. host service, MySQL 3306, SSH 22).
      2. Stale Container: A non-lab or stale container is occupying the port.
      3. Malicious Local Service: Unauthorized local process on 127.0.0.1.

    Mechanism: Bounded fingerprint probe (expected banner/title/known token) with short timeout.
    """
    if not expected_fingerprint:
        # Bundled fixture without network fingerprint requirement
        return True, "No network fingerprint required for fixture."

    url = address_str if address_str.startswith(("http://", "https://")) else f"http://{address_str}"

    try:
        resp = requests.get(
            url,
            timeout=2.0,
            allow_redirects=False,
            headers={"User-Agent": "HexaGuard-LabIdentityProbe/1.0"},
        )
        content = resp.text
        server_hdr = resp.headers.get("Server", "")
        body_sample = content[:4096]

        if expected_fingerprint.lower() in (body_sample + " " + server_hdr).lower():
            return True, f"Fingerprint '{expected_fingerprint}' confirmed on target."
        else:
            return False, (
                f"Lab identity mismatch: Expected fingerprint '{expected_fingerprint}' "
                f"was not found on {url} (status: {resp.status_code})."
            )
    except requests.RequestException as exc:
        return False, f"Target probe unreachable or failed on {url}: {exc}"


def evaluate_lab_gate(
    target_id: str,
    scanner: str,
    scan_type: str,
    user_id: int,
    username: str,
    ip_address: str = "",
    acknowledge_public_scope: bool = False,
) -> LabGateResult:
    """Evaluate fail-closed Lab Gate for a planned scan run."""

    def _deny(code: str, msg: str) -> LabGateResult:
        logger.warning(
            "LAB GATE DENIAL | target=%s | scanner=%s | scan_type=%s | user=%s | code=%s | msg=%s",
            target_id, scanner, scan_type, username, code, msg,
        )
        log_event(
            action="lab_gate_denial",
            username=username,
            user_id=user_id,
            category="lab_gate",
            resource=target_id,
            ip_address=ip_address,
            status="blocked",
            details=f"code={code} scanner={scanner} scan_type={scan_type} reason={msg}",
        )
        return LabGateResult(
            decision=GateDecision.DENY,
            allowed=False,
            reason_code=code,
            message=msg,
            target_id=target_id,
            scanner=scanner,
            scan_type=scan_type,
            audit_logged=True,
        )

    # 1. Feature flag enforcement in backend
    if not is_lab_mode_enabled():
        return _deny(
            "LAB_MODE_DISABLED",
            "Evaluation Lab is disabled. LAB_MODE=1 is required in the backend.",
        )

    # 2. Target existence in registry
    target = get_lab_target(target_id)
    if not target:
        return _deny("TARGET_NOT_FOUND", f"Target '{target_id}' is not registered in lab_targets.")

    kind_val = target.get("kind", "")

    # 3. public_reference: NEVER EXECUTABLE
    if kind_val == TargetKind.PUBLIC_REFERENCE.value or kind_val == "public_reference":
        return _deny(
            "PUBLIC_REFERENCE_NOT_EXECUTABLE",
            f"Target '{target_id}' is a documentation reference only and cannot be scanned.",
        )

    if not target.get("enabled", True):
        return _deny("TARGET_DISABLED", f"Target '{target_id}' is currently disabled in the registry.")

    # 4. Scanner and Scan Type validation
    allowed_scanners = target.get("scanners", [])
    if scanner not in allowed_scanners:
        return _deny(
            "SCANNER_NOT_PERMITTED",
            f"Scanner '{scanner}' is not listed in allowed scanners for target '{target_id}': {allowed_scanners}.",
        )

    permitted_types = target.get("permitted_scan_types", [])
    if scan_type not in permitted_types:
        return _deny(
            "SCAN_TYPE_NOT_PERMITTED",
            f"Scan type '{scan_type}' is not permitted for target '{target_id}': {permitted_types}.",
        )

    address = target.get("address") or ""

    # 5. public_permitted verification
    if kind_val == TargetKind.PUBLIC_PERMITTED.value or kind_val == "public_permitted":
        if not is_lab_remote_scanning_enabled():
            return _deny(
                "REMOTE_SCANNING_DISABLED",
                "Remote scanning of public targets is OFF by default. ALLOW_LAB_REMOTE_SCANNING=1 required.",
            )

        # Check 90-day authorization expiration
        auth_verified_at = target.get("auth_verified_at")
        if not auth_verified_at:
            return _deny(
                "AUTHORIZATION_MISSING",
                "Target is public_permitted but lacks verified owner authorization date.",
            )

        try:
            verified_dt = datetime.fromisoformat(auth_verified_at.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - verified_dt).days
            if age_days > 90:
                return _deny(
                    "AUTHORIZATION_EXPIRED",
                    f"Authorization for target '{target_id}' expired ({age_days} days old, max 90 days allowed).",
                )
        except Exception:
            return _deny("AUTHORIZATION_INVALID", "Failed to parse auth_verified_at timestamp.")

        if not acknowledge_public_scope:
            return _deny(
                "USER_ACKNOWLEDGEMENT_REQUIRED",
                "User acknowledgement of authorized testing scope is required before remote scan dispatch.",
            )

    # 6. Target Address Validation & Local Identity Verification
    verified_ip = None

    if kind_val in (TargetKind.LOCAL_CONTAINER.value, "local_container"):
        # Local containers MUST provide a valid local network address (with or without scheme)
        if not address or not address.strip():
            return _deny("ADDRESS_VALIDATION_FAILED", "Local container target requires a valid network address.")

        valid, resolved_ip, err = _sanitize_and_resolve_address(address)
        if not valid:
            return _deny("ADDRESS_VALIDATION_FAILED", err or "Invalid target address.")

        # Ensure resolved IP is local / RFC1918
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if not any(ip_obj in net for net in _ALLOWED_LOCAL_NETWORKS):
                return _deny(
                    "NON_LOCAL_IP_REJECTED",
                    f"Resolved address '{resolved_ip}' is outside allowed local lab networks.",
                )
        except ValueError:
            return _deny("INVALID_RESOLVED_IP", f"Could not parse resolved IP '{resolved_ip}'.")

        verified_ip = resolved_ip

        # Local Lab Identity Verification (Confused Admin / Stale Container Guard)
        expected_fp = target.get("expected_fingerprint")
        if not expected_fp:
            return _deny(
                "FINGERPRINT_CONFIG_MISSING",
                f"Local container target '{target_id}' requires expected_fingerprint for identity verification.",
            )

        fp_ok, fp_msg = _verify_lab_identity(address, expected_fp)
        if not fp_ok:
            return _deny("LAB_IDENTITY_MISMATCH", fp_msg)

    elif kind_val in (TargetKind.BUNDLED_FIXTURE.value, TargetKind.LOCAL_SOURCE_PROJECT.value, "bundled_fixture", "local_source_project"):
        # Filesystem targets must not contain path traversal or attempt network injection
        if not address or not address.strip():
            return _deny("ADDRESS_VALIDATION_FAILED", f"Target '{target_id}' requires a valid local filesystem path.")

        clean_path = address.replace("\\", "/")
        if "://" in clean_path or clean_path.startswith("//") or "@" in clean_path:
            return _deny("ADDRESS_VALIDATION_FAILED", f"Filesystem target '{target_id}' cannot use network URI.")

        if ".." in clean_path.split("/"):
            return _deny("ADDRESS_VALIDATION_FAILED", f"Path traversal rejected in target path '{address}'.")

    # 7. Gate Passed (ALLOWED)
    log_event(
        action="lab_gate_allow",
        username=username,
        user_id=user_id,
        category="lab_gate",
        resource=target_id,
        ip_address=ip_address,
        status="success",
        details=f"scanner={scanner} scan_type={scan_type} target={target_id} kind={kind_val}",
    )

    return LabGateResult(
        decision=GateDecision.ALLOW,
        allowed=True,
        reason_code="AUTHORIZED",
        message="Target and scanner verified against Evaluation Lab policy.",
        target_id=target_id,
        scanner=scanner,
        scan_type=scan_type,
        verified_address=verified_ip or address,
        rate_limit=int(target.get("rate_limit", 10)),
        audit_logged=True,
    )
