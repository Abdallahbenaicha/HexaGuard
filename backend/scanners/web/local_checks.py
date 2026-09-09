from __future__ import annotations

__all__ = ['logger', '_local_headers', '_local_server_disclosure', '_local_cookies', '_local_cors', '_local_sensitive_paths', '_local_http_methods', '_local_response_body', '_local_https_redirect', '_local_ssl_direct', '_local_waf', '_local_tech']


import base64
import hashlib
import logging
import os
import re
import socket
import ssl
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

try:
    from scanners.web.constants import *
    from scanners.web.utils import *
except ImportError:
    from backend.scanners.web.constants import *
    from backend.scanners.web.utils import *

def _local_headers(headers: dict) -> list[dict]:
    vulns: list[dict] = []
    hl = {k.lower(): v for k, v in headers.items()}

    for name, severity, description in REQUIRED_HEADERS:
        if name.lower() not in hl:
            vulns.append(_vuln(
                f"Missing security header: {name}", severity, description,
                remediation=f"Add to server config: {name}: <value>",
                check="headers",
            ))

    # HSTS quality
    hsts = hl.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15_552_000:
            vulns.append(_vuln("HSTS max-age too short", "medium",
                               f"max-age={m.group(1)} — should be ≥ 15552000 (6 months).",
                               evidence=f"STS: {hsts}", check="headers"))
        if "includeSubDomains" not in hsts:
            vulns.append(_vuln("HSTS missing includeSubDomains", "low",
                               "Subdomains not covered by HSTS policy.", check="headers"))

    # CSP quality
    csp = hl.get("content-security-policy", "")
    if csp:
        csp_l = csp.lower()
        if "unsafe-inline" in csp_l:
            vulns.append(_vuln("CSP: unsafe-inline allowed", "high",
                               "unsafe-inline defeats XSS protection.",
                               evidence=f"CSP: {csp[:200]}", check="headers"))
        if "unsafe-eval" in csp_l:
            vulns.append(_vuln("CSP: unsafe-eval allowed", "medium",
                               "unsafe-eval permits eval() — widens XSS attack surface.",
                               check="headers"))
        if re.search(r"(script-src|default-src)\s+\*", csp_l):
            vulns.append(_vuln("CSP: wildcard script source", "high",
                               "Wildcard (*) in script-src loads scripts from any origin.",
                               check="headers"))
        if "http:" in csp_l and "https:" not in csp_l:
            vulns.append(_vuln("CSP: allows http: sources on HTTPS page", "medium",
                               "Allowing http: sources downgrades mixed-content protection.",
                               check="headers"))
        if "data:" in csp_l and "script-src" in csp_l:
            vulns.append(_vuln("CSP: data: URI allowed in script-src", "medium",
                               "data: URIs in script-src can be used for XSS payloads.",
                               check="headers"))
        if "upgrade-insecure-requests" not in csp_l:
            vulns.append(_vuln("CSP: missing upgrade-insecure-requests", "low",
                               "Add upgrade-insecure-requests to auto-upgrade mixed content.",
                               check="headers"))

    # X-Frame-Options value
    xfo = hl.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        vulns.append(_vuln(f"X-Frame-Options insecure value: {xfo}", "medium",
                           "ALLOW-FROM is obsolete — use CSP frame-ancestors instead.",
                           check="headers"))

    return vulns


def _local_server_disclosure(headers: dict) -> list[dict]:
    vulns: list[dict] = []
    server     = headers.get("Server", "")
    x_powered  = headers.get("X-Powered-By", "")

    for value, header_name in ((server, "Server"), (x_powered, "X-Powered-By")):
        if not value:
            continue
        if re.search(r"\d+\.\d+", value):
            vulns.append(_vuln(
                f"{header_name} header reveals version: {value}", "medium",
                f"{header_name} header exposes software version — aids targeted attacks.",
                remediation="Apache: ServerTokens Prod | Nginx: server_tokens off | "
                            "PHP: expose_php = Off",
                check="disclosure",
            ))
        for pattern, cve, desc, sev in VULN_SERVER_RE:
            if re.search(pattern, value, re.IGNORECASE):
                vulns.append(_vuln(
                    f"Vulnerable server detected — {cve}", sev, desc,
                    evidence=f"{header_name}: {value}",
                    cve_ids=[cve], check="server_cve",
                ))

    return vulns


def _local_cookies(resp: requests.Response) -> list[dict]:
    """
    Parse Set-Cookie headers directly from raw response (including redirect history).
    Avoids using private cookiejar internals — safe across requests versions.
    """
    vulns: list[dict] = []
    seen_names: set[str] = set()

    # Collect raw Set-Cookie values from every hop (redirects + final response)
    raw_headers: list[str] = []
    for hist in resp.history:
        raw_headers += hist.raw.headers.getlist("Set-Cookie")
    raw_headers += resp.raw.headers.getlist("Set-Cookie")

    for raw_cookie in raw_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        if not parts or not parts[0]:
            continue
        name_val = parts[0]
        name = name_val.split("=", 1)[0].strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        # Build lowercase attribute set  {attr_name: value_or_True}
        attrs: dict[str, str | bool] = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            elif part.strip():
                attrs[part.strip().lower()] = True

        is_secure   = "secure"   in attrs
        is_httponly = "httponly" in attrs
        samesite    = attrs.get("samesite")  # str value like "Strict"/"Lax"/"None" or True

        if not is_secure:
            vulns.append(_vuln(f"Cookie missing Secure flag: {name}", "medium",
                               "Cookie transmitted over HTTP — session interception possible.",
                               check="cookies"))
        if not is_httponly:
            vulns.append(_vuln(f"Cookie missing HttpOnly flag: {name}", "medium",
                               "JavaScript can read this cookie — XSS can steal sessions.",
                               check="cookies"))
        if not samesite:
            vulns.append(_vuln(f"Cookie missing SameSite attribute: {name}", "low",
                               "No SameSite attribute — CSRF protection reduced.",
                               check="cookies"))
        elif isinstance(samesite, str) and samesite.lower() == "none" and not is_secure:
            vulns.append(_vuln(f"Cookie SameSite=None without Secure: {name}", "medium",
                               "SameSite=None requires the Secure flag or it will be rejected "
                               "by modern browsers.", check="cookies"))

        # __Secure- prefix violations
        if name.startswith("__Secure-") and not is_secure:
            vulns.append(_vuln(f"__Secure- cookie missing Secure flag: {name}", "high",
                               "__Secure- prefix requires the Secure flag (RFC 8941).",
                               check="cookies"))
        # __Host- prefix violations
        if name.startswith("__Host-"):
            if not is_secure:
                vulns.append(_vuln(f"__Host- cookie missing Secure flag: {name}", "high",
                                   "__Host- requires Secure, no Domain attribute, Path=/.",
                                   check="cookies"))
            elif "domain" in attrs:
                vulns.append(_vuln(f"__Host- cookie has Domain attribute: {name}", "high",
                                   "__Host- must NOT have a Domain attribute.",
                                   check="cookies"))
            elif attrs.get("path") not in ("/", True):
                vulns.append(_vuln(f"__Host- cookie Path is not '/': {name}", "medium",
                                   "__Host- must have Path=/ only.",
                                   check="cookies"))

    return vulns


def _local_cors(url: str, initial_headers: dict, extra_headers: dict | None = None) -> list[dict]:
    """
    Check CORS configuration.
    Creates its own session — thread-safe; does NOT share state with other workers.
    """
    vulns: list[dict] = []
    sess = _make_session(extra_headers)
    hl = {k.lower(): v for k, v in initial_headers.items()}

    acao = hl.get("access-control-allow-origin", "")
    acac = hl.get("access-control-allow-credentials", "").lower()

    # Wildcard + credentials (critical)
    if acao == "*" and acac == "true":
        vulns.append(_vuln(
            "CORS: wildcard origin + credentials=true — critical misconfiguration",
            "critical",
            "Access-Control-Allow-Origin: * combined with credentials=true is invalid "
            "per spec but some parsers accept it — credential theft from any origin.",
            cve_ids=["CWE-942"], check="cors",
        ))
    elif acao == "*":
        vulns.append(_vuln(
            "CORS: wildcard origin (any website can cross-origin request this server)",
            "medium",
            "Access-Control-Allow-Origin: * allows any website to read responses.",
            check="cors",
        ))

    # Test arbitrary origin reflection
    try:
        evil_origin = "https://evil-attacker-securax.com"
        r = sess.get(url, headers={"Origin": evil_origin},
                     timeout=_PROBE_TO, verify=False, allow_redirects=False)
        r_acao = r.headers.get("Access-Control-Allow-Origin", "")
        r_acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if r_acao == evil_origin:
            sev = "critical" if r_acac == "true" else "high"
            vulns.append(_vuln(
                "CORS: arbitrary origin reflected" + (" + credentials" if r_acac == "true" else ""),
                sev,
                "Server reflects arbitrary Origin header back in ACAO. "
                + ("With credentials=true, attacker can steal authenticated session data." if r_acac == "true"
                   else "Attacker can cross-origin read server responses."),
                evidence=f"Sent Origin: {evil_origin} → ACAO: {r_acao}",
                check="cors",
            ))
    except Exception:
        pass

    # Test null origin bypass
    try:
        r2 = sess.get(url, headers={"Origin": "null"},
                      timeout=_PROBE_TO, verify=False, allow_redirects=False)
        if r2.headers.get("Access-Control-Allow-Origin", "").lower() == "null":
            vulns.append(_vuln(
                "CORS: null origin accepted — sandbox bypass possible",
                "high",
                "Server accepts Origin: null, which can be set by sandboxed iframes "
                "and data: URIs — allows cross-origin attacks from attacker-controlled pages.",
                check="cors",
            ))
    except Exception:
        pass

    return vulns


def _local_sensitive_paths(
    url: str,
    extra_headers: dict | None = None,
    rate_limit: int | None = None,
) -> list[dict]:
    """
    Probe sensitive paths with smart soft-404 fingerprinting.
    Gets a 404 baseline first to avoid false positives.
    Each call creates its own session — thread-safe.
    """
    vulns: list[dict] = []
    sess  = _make_session(extra_headers)
    base  = url.rstrip("/")
    fp    = _404_fingerprint(base, sess)

    delay = (1.0 / rate_limit) if (rate_limit and rate_limit > 0) else 0.0

    for path, severity, description in SENSITIVE_PATHS:
        if delay > 0:
            time.sleep(delay)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                r = sess.get(f"{base}{path}", timeout=_PROBE_TO,
                             allow_redirects=False, verify=False)

            if r.status_code != 200:
                continue
            if not r.content:
                continue
            if _is_soft_404(r.content, fp):
                continue

            vulns.append(_vuln(
                f"Sensitive path exposed: {path}", severity, description,
                evidence=f"HTTP 200 — {base}{path} ({len(r.content)} bytes)",
                remediation="Block access: deny from all / Require all denied",
                check="sensitive_paths",
            ))
        except requests.RequestException:
            pass

    return vulns


def _local_http_methods(url: str, extra_headers: dict | None = None) -> list[dict]:
    vulns: list[dict] = []
    try:
        sess = _make_session(extra_headers)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = sess.options(url, timeout=_PROBE_TO, allow_redirects=False, verify=False)
        allow = r.headers.get("Allow", "")
        if allow:
            for method, severity, description in DANGEROUS_METHODS:
                if method in allow.upper():
                    vulns.append(_vuln(
                        f"Dangerous HTTP method: {method}", severity, description,
                        evidence=f"OPTIONS Allow: {allow}",
                        remediation="<LimitExcept GET POST HEAD>\\n  Require all denied\\n</LimitExcept>",
                        check="http_methods",
                    ))
    except Exception:
        pass
    return vulns


def _local_response_body(resp: requests.Response) -> list[dict]:
    vulns: list[dict] = []
    try:
        # Skip very large bodies to prevent MemoryError (e.g. binary downloads)
        cl = int(resp.headers.get("Content-Length", 0) or 0)
        if cl > 10_000_000:
            return vulns
        body = resp.text[:60_000]
    except Exception:
        return vulns
    for pattern, severity, description in ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            vulns.append(_vuln(
                f"Information disclosure: {description.split(' — ')[0]}", severity, description,
                evidence="Pattern matched in HTTP response body",
                remediation="Disable debug mode. Use custom error pages. Never expose internal errors.",
                check="disclosure",
            ))
    return vulns


def _local_https_redirect(url: str, host: str, extra_headers: dict | None = None) -> list[dict]:
    """Own session — thread-safe, no shared state with other workers."""
    vulns: list[dict] = []
    if not url.startswith("https://"):
        return vulns
    try:
        sess = _make_session(extra_headers)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = sess.get(f"http://{host}", timeout=_PROBE_TO,
                         allow_redirects=True, verify=False)
        if not r.url.startswith("https://"):
            vulns.append(_vuln(
                "HTTP not redirected to HTTPS",
                "high",
                "Plain HTTP is accessible without redirect to HTTPS — data sent unencrypted.",
                evidence=f"http://{host} → {r.url}",
                remediation="Redirect: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
                check="https_redirect",
            ))
    except Exception:
        pass
    return vulns


def _local_ssl_direct(host: str) -> list[dict]:
    """Direct TLS check: deprecated protocol negotiation, cert expiry."""
    vulns: list[dict] = []
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=6),
            server_hostname=host,
        )
        cert        = conn.getpeercert()
        tls_version = conn.version()
        conn.close()

        if tls_version in ("TLSv1", "TLSv1.1"):
            vulns.append(_vuln(f"Deprecated TLS version: {tls_version}", "high",
                               f"Python negotiated {tls_version} — server still supports deprecated protocol.",
                               check="ssl"))

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    vulns.append(_vuln("SSL Certificate EXPIRED", "critical",
                                       f"Expired {-days} days ago.", check="ssl"))
                elif days < 7:
                    vulns.append(_vuln(f"SSL Certificate expires in {days} days", "critical",
                                       "Immediate renewal required.", check="ssl"))
                elif days < 30:
                    sev = "high" if days < 14 else "medium"
                    vulns.append(_vuln(f"SSL Certificate expires in {days} days", sev,
                                       f"Renew before {exp.strftime('%Y-%m-%d')}.", check="ssl"))
            except ValueError:
                pass

    except ssl.SSLError as exc:
        vulns.append(_vuln("SSL/TLS error", "critical", str(exc), check="ssl"))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return vulns


def _local_waf(headers: dict) -> list[dict]:
    """Detect WAF / CDN presence from response headers."""
    vulns: list[dict] = []
    hl = {k.lower(): v.lower() for k, v in headers.items()}
    detected: list[str] = []

    for name, checks in _WAF_SIGS.items():
        for header_key, header_val in checks:
            if header_key in hl:
                if header_val is None or header_val.lower() in hl[header_key]:
                    detected.append(name)
                    break

    if detected:
        vulns.append(_vuln(
            f"WAF/CDN detected: {', '.join(detected)}",
            "info",
            f"The following WAF/CDN layers were identified: {', '.join(detected)}. "
            "This is informational — verify security policies are correctly configured.",
            check="waf_detection",
        ))
    return vulns


def _local_tech(resp: requests.Response) -> list[dict]:
    """Fingerprint technology stack from headers, cookies, response body."""
    vulns: list[dict] = []
    hl     = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = " ".join(c.name for c in resp.cookies)
    try:
        body = resp.text[:40_000]
    except Exception:
        body = ""

    detected: list[str] = []
    for tech, sigs in _TECH_SIGS.items():
        for sig_type, pattern in sigs:
            try:
                if sig_type == "header":
                    target = " ".join(f"{k}: {v}" for k, v in hl.items())
                elif sig_type == "cookie":
                    target = cookies_str
                else:
                    target = body
                if re.search(pattern, target, re.IGNORECASE):
                    detected.append(tech)
                    break
            except Exception:
                pass

    if detected:
        vulns.append(_vuln(
            f"Technology stack identified: {', '.join(detected)}",
            "info",
            f"Detected: {', '.join(detected)}. Ensure all components are up-to-date "
            "and hardened for production use.",
            check="tech_detection",
        ))
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

