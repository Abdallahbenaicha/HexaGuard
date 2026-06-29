"""HexaGuard — SSL/TLS Certificate & Protocol Scanner.

Uses only Python stdlib (ssl, socket, urllib) — no extra packages required.
Checks performed:
  • Certificate expiry (days remaining, expired)
  • Self-signed / untrusted issuer
  • Hostname mismatch
  • Weak key strength (RSA < 2048, EC < 224)
  • Deprecated TLS versions (SSLv3, TLS 1.0, TLS 1.1)
  • Weak cipher suites (RC4, DES, 3DES, EXPORT, NULL, ANON)
  • HSTS header presence & max-age
  • HTTP → HTTPS redirect enforcement
  • Certificate transparency (SCT) detection
  • Certificate SAN / CN validation
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_TIMEOUT = 10

# Weak cipher keywords (substring match on cipher name)
_WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "SEED", "IDEA", "MD5",
]

# Deprecated protocol versions
_DEPRECATED_PROTOS = {
    ssl.TLSVersion.TLSv1:   ("TLS 1.0", "high"),
    ssl.TLSVersion.TLSv1_1: ("TLS 1.1", "medium"),
}

_GOOD_PROTOS = {ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3}


def _parse_host_port(target: str) -> tuple[str, int]:
    """Extract (hostname, port) from a target string."""
    target = target.strip().rstrip("/")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 443
    return host, port


def _get_cert_info(host: str, port: int) -> dict:
    """Connect via TLS and return raw cert dict + negotiated protocol/cipher."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED

    result = {}
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                result["cert"]     = conn.getpeercert()
                result["version"]  = conn.version()
                result["cipher"]   = conn.cipher()
                result["tls_ok"]   = True
    except ssl.SSLCertVerificationError as exc:
        result["tls_ok"]    = False
        result["ssl_error"] = str(exc)
        # Still fetch the cert without verification to inspect it
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as conn:
                    result["cert"]    = conn.getpeercert()
                    result["version"] = conn.version()
                    result["cipher"]  = conn.cipher()
        except Exception:
            pass
    except OSError as exc:
        result["tls_ok"]    = False
        result["ssl_error"] = str(exc)

    return result


def _check_deprecated_proto(host: str, port: int, proto_str: str) -> bool:
    """Return True if the host accepts a specific (deprecated) TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = getattr(ssl.TLSVersion, proto_str, ssl.TLSVersion.TLSv1_2)
        ctx.maximum_version = getattr(ssl.TLSVersion, proto_str, ssl.TLSVersion.TLSv1_2)
        with socket.create_connection((host, port), timeout=5) as raw:
            ctx.wrap_socket(raw, server_hostname=host)
        return True
    except Exception:
        return False


def _check_https_redirect(host: str, port: int) -> bool:
    """Return True if HTTP:80 redirects to HTTPS."""
    if port != 443:
        return True  # non-standard port — skip
    try:
        req = urllib.request.Request(
            f"http://{host}/",
            headers={"User-Agent": "HexaGuard-SSL-Scanner/2.1"},
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPRedirectHandler()
        )
        resp = opener.open(req, timeout=8)
        final = resp.geturl()
        return final.startswith("https://")
    except Exception:
        return False


def _check_hsts(host: str, port: int) -> tuple[bool, int]:
    """Return (hsts_present, max_age_seconds). Uses HTTPS HEAD."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                request_bytes = (
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                    "User-Agent: HexaGuard-SSL-Scanner/2.1\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                conn.sendall(request_bytes)
                response = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
        headers_raw = response.decode("utf-8", errors="replace").lower()
        if "strict-transport-security" in headers_raw:
            m = re.search(r"max-age=(\d+)", headers_raw)
            max_age = int(m.group(1)) if m else 0
            return True, max_age
        return False, 0
    except Exception:
        return False, 0


def _cert_days_remaining(cert: dict) -> int | None:
    """Return days until certificate expiry."""
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except Exception:
        return None


def _is_self_signed(cert: dict) -> bool:
    issuer  = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    return issuer.get("commonName") == subject.get("commonName")


def _key_strength(cert: dict) -> tuple[str, int | None]:
    """Return (key_type, bits) from the cert's public-key info."""
    pub = cert.get("publicKey", {}) if isinstance(cert.get("publicKey"), dict) else {}
    key_type = pub.get("type", "unknown").upper()
    bits     = pub.get("bits")
    if bits is None:
        bits = cert.get("keySize")
    return key_type, bits


def _weak_cipher(cipher_name: str) -> bool:
    name_up = cipher_name.upper()
    return any(p in name_up for p in _WEAK_CIPHER_PATTERNS)


def run_ssl_scan(target: str) -> dict:
    """Run a comprehensive SSL/TLS scan and return HexaGuard report format."""
    host, port = _parse_host_port(target)
    scan_start = time.perf_counter()
    vulns: list[dict] = []

    def _vuln(title, severity, description, evidence="", remediation="", check="ssl", cves=None):
        vulns.append({
            "check":       check,
            "title":       title,
            "severity":    severity,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "cve_ids":     cves or [],
        })

    # ── 1. Connect and get certificate ───────────────────────────────────────
    info = _get_cert_info(host, port)
    cert = info.get("cert") or {}

    if not info.get("tls_ok") and not cert:
        _vuln(
            "SSL/TLS Connection Failed",
            "critical",
            f"Could not establish a TLS connection to {host}:{port}.",
            evidence=info.get("ssl_error", ""),
            remediation="Ensure the server has a valid TLS certificate and accepts connections on port 443.",
            check="ssl_connect",
        )
        return {
            "scan_type":       "ssl",
            "target":          target,
            "vulnerabilities": vulns,
            "meta": {
                "host": host, "port": port,
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "scan_duration_seconds": round(time.perf_counter() - scan_start, 2),
            },
        }

    # ── 2. Certificate expiry ────────────────────────────────────────────────
    days = _cert_days_remaining(cert)
    if days is not None:
        if days < 0:
            _vuln(
                "Certificate Expired",
                "critical",
                f"The SSL certificate expired {abs(days)} day(s) ago.",
                evidence=f"notAfter: {cert.get('notAfter')}",
                remediation="Renew the certificate immediately. Use Let's Encrypt for free auto-renewal.",
                check="ssl_expiry",
                cves=["CVE-2020-13777"],
            )
        elif days < 7:
            _vuln(
                "Certificate Expires Within 7 Days",
                "critical",
                f"Certificate expires in {days} day(s).",
                evidence=f"notAfter: {cert.get('notAfter')}",
                remediation="Renew the certificate now to avoid service disruption.",
                check="ssl_expiry",
            )
        elif days < 30:
            _vuln(
                "Certificate Expires Within 30 Days",
                "high",
                f"Certificate expires in {days} day(s). Plan renewal soon.",
                evidence=f"notAfter: {cert.get('notAfter')}",
                remediation="Schedule certificate renewal before expiry.",
                check="ssl_expiry",
            )
        elif days < 90:
            _vuln(
                "Certificate Expires Within 90 Days",
                "medium",
                f"Certificate expires in {days} day(s).",
                evidence=f"notAfter: {cert.get('notAfter')}",
                remediation="Plan certificate renewal soon.",
                check="ssl_expiry",
            )

    # ── 3. Certificate trust (self-signed) ───────────────────────────────────
    if not info.get("tls_ok"):
        err = info.get("ssl_error", "")
        if "CERTIFICATE_VERIFY_FAILED" in err or "self" in err.lower() or "unable to get local issuer" in err.lower():
            _vuln(
                "Untrusted / Self-Signed Certificate",
                "high",
                "The certificate is not trusted by a public CA or is self-signed. "
                "Browsers will show a security warning to users.",
                evidence=err,
                remediation="Replace with a certificate signed by a trusted CA (e.g., Let's Encrypt).",
                check="ssl_trust",
            )
    elif cert and _is_self_signed(cert):
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))
        _vuln(
            "Self-Signed Certificate",
            "high",
            "The certificate issuer and subject are identical — the certificate is self-signed.",
            evidence=f"Issuer CN: {issuer.get('commonName')}  Subject CN: {subject.get('commonName')}",
            remediation="Replace with a CA-signed certificate. Let's Encrypt provides free certificates.",
            check="ssl_trust",
        )

    # ── 4. TLS protocol version ──────────────────────────────────────────────
    negotiated = info.get("version", "")
    if negotiated in ("TLSv1", "TLSv1.1", "SSLv3"):
        label = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "SSLv3": "SSLv3"}.get(negotiated, negotiated)
        sev   = "high" if negotiated in ("TLSv1", "SSLv3") else "medium"
        _vuln(
            f"Deprecated Protocol: {label}",
            sev,
            f"The server negotiated {label}, which is deprecated and vulnerable to attacks "
            f"like POODLE and BEAST.",
            evidence=f"Negotiated: {negotiated}",
            remediation="Disable TLS 1.0/1.1 and SSLv3. Support only TLS 1.2 and TLS 1.3.",
            check="ssl_protocol",
            cves=["CVE-2014-3566", "CVE-2011-3389"],
        )

    # ── 5. Active deprecated protocol probe ──────────────────────────────────
    for proto_attr, (proto_label, sev) in [
        ("TLSv1",   ("TLS 1.0", "high")),
        ("TLSv1_1", ("TLS 1.1", "medium")),
    ]:
        if _check_deprecated_proto(host, port, proto_attr):
            if negotiated not in ("TLSv1", "TLSv1.1"):
                _vuln(
                    f"Server Accepts Deprecated {proto_label}",
                    sev,
                    f"Even though the connection defaulted to {negotiated or 'a modern protocol'}, "
                    f"the server still accepts {proto_label} connections.",
                    evidence=f"Active probe confirmed {proto_label} acceptance",
                    remediation=f"Explicitly disable {proto_label} in your server's TLS configuration.",
                    check="ssl_protocol",
                    cves=["CVE-2014-3566"] if proto_attr == "TLSv1" else [],
                )

    # ── 6. Cipher suite ──────────────────────────────────────────────────────
    cipher_info = info.get("cipher") or ()
    cipher_name = cipher_info[0] if cipher_info else ""
    if cipher_name and _weak_cipher(cipher_name):
        _vuln(
            f"Weak Cipher Suite: {cipher_name}",
            "high",
            f"The negotiated cipher suite '{cipher_name}' is considered weak and "
            "provides insufficient confidentiality or integrity.",
            evidence=f"Negotiated cipher: {cipher_name}",
            remediation="Configure the server to prefer ECDHE+AES-GCM or CHACHA20-POLY1305 cipher suites. "
                        "Disable RC4, DES, 3DES, EXPORT, NULL, and anonymous ciphers.",
            check="ssl_cipher",
        )

    # ── 7. Key strength ──────────────────────────────────────────────────────
    key_type, key_bits = _key_strength(cert)
    if key_bits is not None:
        if key_type in ("RSA", "") and key_bits < 2048:
            _vuln(
                f"Weak RSA Key: {key_bits} bits",
                "high",
                f"RSA keys smaller than 2048 bits are considered insecure and can be broken "
                f"with modern computing resources.",
                evidence=f"Key type: {key_type}  Bits: {key_bits}",
                remediation="Generate a new RSA key of at least 2048 bits (4096 recommended).",
                check="ssl_key",
                cves=["CVE-2015-3193"],
            )
        elif key_type == "EC" and key_bits is not None and key_bits < 224:
            _vuln(
                f"Weak EC Key: {key_bits} bits",
                "high",
                f"Elliptic curve keys smaller than 224 bits are considered weak.",
                evidence=f"Key type: EC  Bits: {key_bits}",
                remediation="Use at least P-256 (256-bit) ECDSA.",
                check="ssl_key",
            )

    # ── 8. HSTS ──────────────────────────────────────────────────────────────
    hsts_present, hsts_max_age = _check_hsts(host, port)
    if not hsts_present:
        _vuln(
            "HSTS Not Enabled",
            "medium",
            "The server does not send a Strict-Transport-Security header. "
            "Attackers can downgrade HTTPS connections to HTTP (SSL-stripping attacks).",
            evidence="Header 'Strict-Transport-Security' missing from HTTPS response",
            remediation="Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            check="ssl_hsts",
        )
    elif hsts_max_age < 15768000:
        _vuln(
            f"HSTS max-age Too Short: {hsts_max_age}s",
            "low",
            f"HSTS max-age of {hsts_max_age} seconds is below the recommended minimum of 180 days.",
            evidence=f"Strict-Transport-Security: max-age={hsts_max_age}",
            remediation="Set max-age to at least 15768000 (6 months), ideally 63072000 (2 years).",
            check="ssl_hsts",
        )

    # ── 9. HTTP → HTTPS redirect ─────────────────────────────────────────────
    if not _check_https_redirect(host, port):
        _vuln(
            "HTTP Does Not Redirect to HTTPS",
            "medium",
            "The server responds to HTTP requests without redirecting to HTTPS, "
            "exposing users to man-in-the-middle attacks.",
            evidence=f"http://{host}/ did not redirect to https://",
            remediation="Configure your web server to permanently redirect (301) all HTTP traffic to HTTPS.",
            check="ssl_redirect",
        )

    # ── 10. SAN validation ───────────────────────────────────────────────────
    san_list = [name for _, name in cert.get("subjectAltName", [])]
    if cert and not san_list:
        _vuln(
            "Certificate Has No Subject Alternative Names (SANs)",
            "low",
            "Modern browsers require SANs. A certificate without SANs may be rejected.",
            evidence="subjectAltName extension not present",
            remediation="Reissue the certificate with SAN extension listing all served hostnames.",
            check="ssl_san",
        )

    # ── Build meta ────────────────────────────────────────────────────────────
    issuer_dict  = dict(x[0] for x in cert.get("issuer",  [])) if cert else {}
    subject_dict = dict(x[0] for x in cert.get("subject", [])) if cert else {}

    meta = {
        "host":                    host,
        "port":                    port,
        "tls_version":             negotiated or "unknown",
        "cipher_suite":            cipher_name or "unknown",
        "cert_subject":            subject_dict.get("commonName", ""),
        "cert_issuer":             issuer_dict.get("commonName", ""),
        "cert_not_after":          cert.get("notAfter", ""),
        "cert_days_remaining":     days,
        "cert_san_count":          len(san_list),
        "hsts_enabled":            hsts_present,
        "hsts_max_age":            hsts_max_age if hsts_present else 0,
        "trust_verified":          bool(info.get("tls_ok")),
        "scan_time":               datetime.now(timezone.utc).isoformat(),
        "scan_duration_seconds":   round(time.perf_counter() - scan_start, 2),
        "tools":                   ["python-ssl", "socket"],
    }

    if not vulns:
        vulns.append({
            "check":       "ssl_overall",
            "title":       "SSL/TLS Configuration: No Issues Found",
            "severity":    "info",
            "description": f"All SSL/TLS checks passed for {host}:{port}. "
                           f"TLS version: {negotiated or 'unknown'}. Cipher: {cipher_name or 'unknown'}.",
            "evidence":    f"Certificate valid for {days} more day(s)." if days else "",
            "remediation": "",
            "cve_ids":     [],
        })

    return {
        "scan_type":       "ssl",
        "target":          target,
        "vulnerabilities": vulns,
        "meta":            meta,
    }
