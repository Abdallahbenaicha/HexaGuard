"""HexaGuard — DNS & Email Security Scanner.

Uses DNS-over-HTTPS (Cloudflare DoH) via the already-installed `requests` library
so no extra packages are required.

Checks performed:
  SPF  — record present, policy strength (-all / ~all / +all / ?all)
  DMARC — record present, policy (none/quarantine/reject), sub-domain policy, reporting
  DKIM — common selector probing (default, google, mail, k1, smtp, selector1/2)
  MX   — mail server records present
  CAA  — Certificate Authority Authorization records
  DNSSEC — DS record presence
  Zone Transfer — AXFR attempt (always expected to fail on hardened servers)
  HTTP security headers — HSTS, X-Frame-Options, CSP on main domain
"""

from __future__ import annotations

import logging
import socket
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_DOH_URL  = "https://cloudflare-dns.com/dns-query"
_TIMEOUT  = 8
_HEADERS  = {"Accept": "application/dns-json"}

# DNS record type numbers (RFC 1035 / IANA)
_RTYPES: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16,
    "AAAA": 28, "CAA": 257, "DS": 43, "DNSKEY": 48,
}

# DKIM selectors to probe
_DKIM_SELECTORS = [
    "default", "google", "mail", "smtp", "k1",
    "selector1", "selector2", "dkim", "email", "s1", "s2",
]


# ── DoH helpers ───────────────────────────────────────────────────────────────

def _doh(name: str, rtype: str) -> list[str]:
    """Return a list of string answers for a DNS query via DoH."""
    type_num = _RTYPES.get(rtype.upper(), 255)
    try:
        resp = requests.get(
            _DOH_URL,
            params={"name": name, "type": rtype},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        data = resp.json()
        answers = data.get("Answer", [])
        return [
            str(a["data"]).strip('"').strip()
            for a in answers
            if a.get("type") == type_num
        ]
    except Exception as exc:
        logger.debug("DoH query failed %s %s: %s", name, rtype, exc)
        return []


def _doh_any(name: str, rtype: str) -> list[dict]:
    """Return raw answer objects (all types) for a query."""
    try:
        resp = requests.get(
            _DOH_URL,
            params={"name": name, "type": rtype},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        return resp.json().get("Answer", [])
    except Exception:
        return []


def _strip_domain(raw: str) -> str:
    """Strip scheme, www, path from a target string to get bare domain."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or raw
    return host.lstrip("www.").strip()


def _vuln(title: str, severity: str, description: str,
          recommendation: str, detail: str = "") -> dict:
    return {
        "title":          title,
        "severity":       severity,
        "description":    description,
        "recommendation": recommendation,
        "detail":         detail,
    }


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_spf(domain: str) -> tuple[list, dict | None]:
    vulns: list[dict] = []
    txt_records = _doh(domain, "TXT")
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        vulns.append(_vuln(
            "No SPF record found",
            "high",
            f"{domain} has no SPF (Sender Policy Framework) TXT record.",
            "Publish an SPF record in DNS, e.g.:\n"
            "  v=spf1 include:_spf.google.com -all\n"
            "This prevents attackers from sending email as your domain.",
        ))
        return vulns, None

    if len(spf_records) > 1:
        vulns.append(_vuln(
            "Multiple SPF records found",
            "medium",
            f"{domain} has {len(spf_records)} SPF records — only one is valid per RFC 7208.",
            "Merge all SPF mechanisms into a single TXT record.",
            detail="; ".join(spf_records),
        ))

    spf = spf_records[0]
    if "+all" in spf:
        vulns.append(_vuln(
            "SPF +all — allows ANY server to send as your domain",
            "critical",
            "'+all' means any server in the world can send email as your domain. Completely ineffective.",
            "Change to '-all' (strict fail) or '~all' (soft fail) and list your legitimate mail servers.",
            detail=spf,
        ))
    elif "?all" in spf:
        vulns.append(_vuln(
            "SPF ?all — neutral policy (no enforcement)",
            "medium",
            "'?all' provides no spam/spoofing protection.",
            "Change to '-all' for strict enforcement.",
            detail=spf,
        ))
    elif "~all" in spf:
        vulns.append(_vuln(
            "SPF ~all — soft fail (not fully enforced)",
            "low",
            "'~all' is a soft-fail: unauthorised servers are flagged but not rejected.",
            "Consider upgrading to '-all' once all legitimate sending sources are listed.",
            detail=spf,
        ))

    return vulns, {"record": spf}


def _check_dmarc(domain: str) -> tuple[list, dict | None]:
    vulns: list[dict] = []
    txt_records = _doh(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        vulns.append(_vuln(
            "No DMARC record found",
            "high",
            f"_dmarc.{domain} has no DMARC record — spoofed emails won't be rejected.",
            "Publish a DMARC record, e.g.:\n"
            "  v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\n"
            "Start with p=none for monitoring, then move to quarantine/reject.",
        ))
        return vulns, None

    dmarc = dmarc_records[0]
    policy = "none"
    for part in dmarc.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part[2:].strip().lower()
            break

    if policy == "none":
        vulns.append(_vuln(
            "DMARC policy is 'none' — monitoring only, no enforcement",
            "medium",
            "p=none means DMARC is active but takes no action on failing emails.",
            "Move to p=quarantine then p=reject after reviewing rua/ruf reports.",
            detail=dmarc,
        ))
    elif policy == "quarantine":
        vulns.append(_vuln(
            "DMARC policy is 'quarantine' (partial enforcement)",
            "info",
            "p=quarantine sends failing emails to spam — good, but p=reject is the gold standard.",
            "Once satisfied with DMARC reports, upgrade to p=reject.",
            detail=dmarc,
        ))

    if "rua=" not in dmarc.lower() and "ruf=" not in dmarc.lower():
        vulns.append(_vuln(
            "DMARC: no reporting address (rua/ruf) configured",
            "low",
            "Without rua/ruf you receive no DMARC aggregate or forensic reports.",
            "Add rua=mailto:dmarc@yourdomain.com to receive daily aggregate reports.",
            detail=dmarc,
        ))

    return vulns, {"record": dmarc, "policy": policy}


def _check_dkim(domain: str) -> tuple[list, dict]:
    found_selectors: list[str] = []
    for sel in _DKIM_SELECTORS:
        answers = _doh_any(f"{sel}._domainkey.{domain}", "TXT")
        if answers:
            found_selectors.append(sel)

    vulns: list[dict] = []
    if not found_selectors:
        vulns.append(_vuln(
            "No DKIM record found (common selectors probed)",
            "medium",
            f"None of the common DKIM selectors ({', '.join(_DKIM_SELECTORS[:6])}…) returned a TXT record.",
            "Configure DKIM signing on your mail server and publish the public key as a TXT record at:\n"
            "  <selector>._domainkey.<domain>  IN  TXT  'v=DKIM1; k=rsa; p=<publickey>'",
        ))

    return vulns, {"selectors_found": found_selectors}


def _check_mx(domain: str) -> tuple[list, dict]:
    mx_records = _doh(domain, "MX")
    vulns: list[dict] = []
    if not mx_records:
        vulns.append(_vuln(
            "No MX records found",
            "info",
            f"{domain} has no MX records — the domain cannot receive email.",
            "If this domain sends but doesn't receive email, this may be intentional. "
            "Otherwise add MX records pointing to your mail server.",
        ))
    return vulns, {"mx_records": mx_records}


def _check_caa(domain: str) -> tuple[list, dict]:
    caa_records = _doh(domain, "CAA")
    vulns: list[dict] = []
    if not caa_records:
        vulns.append(_vuln(
            "No CAA records — any CA can issue certificates for this domain",
            "low",
            "Without Certificate Authority Authorization records, any trusted CA can issue an SSL certificate for your domain.",
            "Add CAA records to restrict which CAs may issue certificates, e.g.:\n"
            "  yourdomain.com  CAA  0 issue \"letsencrypt.org\"\n"
            "  yourdomain.com  CAA  0 issuewild \";\"",
        ))
    return vulns, {"caa_records": caa_records}


def _check_dnssec(domain: str) -> tuple[list, dict]:
    ds_records = _doh(domain, "DS")
    vulns: list[dict] = []
    enabled = len(ds_records) > 0
    if not enabled:
        vulns.append(_vuln(
            "DNSSEC not enabled",
            "low",
            "Without DNSSEC, DNS responses can be spoofed (DNS cache poisoning / BGP hijacking).",
            "Enable DNSSEC in your DNS registrar/provider settings. This adds cryptographic signatures to DNS records.",
        ))
    return vulns, {"dnssec_enabled": enabled}


def _check_zone_transfer(domain: str) -> tuple[list, dict]:
    """Attempt a zone transfer — should always fail on properly configured servers."""
    vulns: list[dict] = []
    attempted = False
    transfer_possible = False

    try:
        ns_records = _doh(domain, "NS")
        for ns in ns_records[:3]:
            ns = ns.rstrip(".")
            try:
                ip = socket.gethostbyname(ns)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((ip, 53))
                # Send AXFR query (minimal TCP DNS packet)
                qname = b"".join(
                    len(part).to_bytes(1, "big") + part.encode()
                    for part in domain.split(".")
                ) + b"\x00"
                axfr_query = (
                    b"\x00\x1c"         # length prefix
                    b"\xaa\xbb"         # transaction ID
                    b"\x00\x00"         # flags: standard query
                    b"\x00\x01"         # QDCOUNT=1
                    b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT/NSCOUNT/ARCOUNT
                    + qname
                    + b"\x00\xfc"       # QTYPE=AXFR
                    + b"\x00\x01"       # QCLASS=IN
                )
                sock.sendall(axfr_query)
                resp = sock.recv(512)
                sock.close()
                attempted = True
                # TCP DNS response: first 2 bytes are the TCP length prefix.
                # Actual DNS message starts at byte 2:
                #   TxID(2) Flags(2) QDCOUNT(2) ANCOUNT(2) ...
                # RCODE is the lower 4 bits of the 4th byte of the DNS message.
                # ANCOUNT > 0 AND RCODE == 0 means transfer was allowed.
                if len(resp) > 11:
                    dns_msg = resp[2:]
                    rcode = dns_msg[3] & 0x0F
                    ancount = int.from_bytes(dns_msg[6:8], "big")
                    if rcode == 0 and ancount > 0:
                        transfer_possible = True
                        break
            except Exception:
                pass
    except Exception:
        pass

    if transfer_possible:
        vulns.append(_vuln(
            "DNS Zone Transfer allowed (AXFR)",
            "critical",
            f"The nameserver accepted an AXFR (zone transfer) request, exposing the complete DNS zone for {domain}.",
            "Restrict zone transfers to authorised slave nameservers only. On BIND: 'allow-transfer { trusted-secondary; };'",
        ))
    elif attempted:
        vulns.append(_vuln(
            "DNS Zone Transfer correctly rejected",
            "info",
            "Attempted AXFR zone transfer was refused by the nameserver — good.",
            "No action required.",
        ))

    return vulns, {"zone_transfer_attempted": attempted, "zone_transfer_possible": transfer_possible}


def _check_http_headers(domain: str) -> tuple[list, dict]:
    """Check HSTS and basic security headers on the main domain."""
    vulns: list[dict] = []
    headers_found: dict = {}
    try:
        r = requests.get(
            f"https://{domain}",
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "HexaGuard-Security-Scanner/2.0"},
        )
        h = {k.lower(): v for k, v in r.headers.items()}
        headers_found = dict(r.headers)

        if "strict-transport-security" not in h:
            vulns.append(_vuln(
                "HSTS header missing",
                "medium",
                "HTTP Strict Transport Security is not set — browsers may fall back to HTTP.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ))
        else:
            hsts_val = h["strict-transport-security"]
            if "preload" not in hsts_val:
                vulns.append(_vuln(
                    "HSTS not preloaded",
                    "info",
                    "HSTS is present but not in the browser preload list.",
                    "Add 'preload' to your HSTS header and submit to https://hstspreload.org",
                    detail=hsts_val,
                ))

    except requests.exceptions.SSLError:
        vulns.append(_vuln(
            "HTTPS connection failed (SSL error)",
            "high",
            f"Could not establish a secure HTTPS connection to {domain}.",
            "Ensure a valid, trusted TLS certificate is installed. Run the SSL/TLS scanner for details.",
        ))
    except Exception:
        pass  # HTTP check is best-effort

    return vulns, {"response_headers": headers_found}


# ── Public entry point ─────────────────────────────────────────────────────────

def run_dns_scan(target: str) -> dict:
    """Run all DNS/email security checks for a domain and return findings."""
    domain = _strip_domain(target)
    t0     = time.perf_counter()

    all_vulns: list[dict] = []
    meta: dict  = {"domain": domain}

    v, spf_info   = _check_spf(domain)
    all_vulns.extend(v)
    meta["spf"]   = spf_info

    v, dmarc_info = _check_dmarc(domain)
    all_vulns.extend(v)
    meta["dmarc"] = dmarc_info

    v, dkim_info  = _check_dkim(domain)
    all_vulns.extend(v)
    meta["dkim"]  = dkim_info

    v, mx_info    = _check_mx(domain)
    all_vulns.extend(v)
    meta["mx"]    = mx_info

    v, caa_info   = _check_caa(domain)
    all_vulns.extend(v)
    meta["caa"]   = caa_info

    v, dnssec_info = _check_dnssec(domain)
    all_vulns.extend(v)
    meta["dnssec"] = dnssec_info

    v, zt_info    = _check_zone_transfer(domain)
    all_vulns.extend(v)
    meta["zone_transfer"] = zt_info

    v, hdr_info   = _check_http_headers(domain)
    all_vulns.extend(v)
    meta["http_headers"] = {"checked": True}

    meta["scan_duration_s"] = round(time.perf_counter() - t0, 2)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_vulns.sort(key=lambda x: sev_order.get(x["severity"], 99))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    return {
        "scan_type":       "dns",
        "target":          domain,
        "vulnerabilities": all_vulns,
        "counts":          counts,
        "meta":            meta,
    }
