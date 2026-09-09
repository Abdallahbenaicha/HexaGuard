from __future__ import annotations

__all__ = ['logger', '_api_ssllabs', '_api_observatory', '_api_shodan', '_api_virustotal', '_api_abuseipdb', '_api_google_safebrowsing', '_api_urlscan', '_api_urlhaus', '_api_greynoise', '_api_ipinfo', '_api_crtsh', '_api_dns_security']


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

def _api_ssllabs(host: str) -> tuple[list[dict], dict]:
    """
    Qualys SSL Labs API v3 — industry standard TLS grading.
    https://www.ssllabs.com/ssltest/
    Free, no key required.
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    sess = _make_session()
    base = "https://api.ssllabs.com/api/v3"

    try:
        r = sess.get(f"{base}/analyze",
                     params={"host": host, "all": "done", "ignoreMismatch": "on"},
                     timeout=_API_TO)
        if r.status_code != 200:
            return vulns, {"ssllabs_error": f"HTTP {r.status_code}"}

        data = r.json()
        waited = 0
        while data.get("status") not in ("READY", "ERROR") and waited < _SSLLABS_MAX:
            time.sleep(_SSLLABS_POLL)
            waited += _SSLLABS_POLL
            r    = sess.get(f"{base}/analyze",
                            params={"host": host, "all": "done"}, timeout=_API_TO)
            data = r.json()

        if data.get("status") == "ERROR":
            return vulns, {"ssllabs_error": data.get("statusMessage", "SSL Labs error")}
        if data.get("status") != "READY":
            return vulns, {"ssllabs_error": f"SSL Labs timed out after {_SSLLABS_MAX}s"}

        grades = []
        for ep in data.get("endpoints", []):
            grade   = ep.get("grade", "")
            details = ep.get("details", {}) or {}
            if grade:
                grades.append(grade)

            # Weak grade
            if grade and grade not in ("A", "A+", "A-", "B"):
                sev = "critical" if grade in ("F", "T") else "high" if grade in ("C", "D") else "medium"
                vulns.append(_vuln(
                    f"SSL Labs grade: {grade}",
                    sev,
                    f"TLS configuration is weak. Grade {grade} for {host}. "
                    "Review cipher suites, protocol versions and certificate chain.",
                    evidence=f"SSL Labs: {grade}",
                    remediation="Enable TLS 1.3, disable TLS 1.0/1.1, use strong ciphers. "
                                "Reference: https://ssl-config.mozilla.org/",
                    check="ssl_labs",
                ))

            # Deprecated protocols
            for proto in details.get("protocols", []):
                ver = proto.get("version", "")
                if ver in ("1.0", "1.1"):
                    vulns.append(_vuln(
                        f"Deprecated TLS {ver} supported",
                        "high",
                        f"TLS {ver} deprecated RFC 8996 — must be disabled.",
                        evidence=f"SSL Labs detected TLS {ver} on {host}",
                        remediation="SSLProtocol -all +TLSv1.2 +TLSv1.3",
                        check="ssl_labs",
                    ))

            # SSL 3.0
            if details.get("sslv3"):
                vulns.append(_vuln(
                    "SSL 3.0 enabled (POODLE)",
                    "critical",
                    "SSLv3 is broken and vulnerable to POODLE attack.",
                    check="ssl_labs",
                ))

            # Certificate expiry
            cert = details.get("cert") or {}
            not_after = cert.get("notAfter", 0)
            if not_after:
                exp       = datetime.fromtimestamp(not_after / 1000, tz=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    vulns.append(_vuln("SSL Certificate EXPIRED", "critical",
                                       f"Expired {-days_left} days ago.", check="ssl_labs"))
                elif days_left < 7:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "critical",
                                       "Immediate renewal required.", check="ssl_labs"))
                elif days_left < 14:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "high",
                                       "Renew urgently.", check="ssl_labs"))
                elif days_left < 30:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "medium",
                                       f"Renew before {exp.strftime('%Y-%m-%d')}.", check="ssl_labs"))

            # Self-signed — check selfSigned flag directly (issues==0 is a separate concern)
            if cert.get("selfSigned"):
                vulns.append(_vuln("Self-signed SSL certificate", "high",
                                   "Certificate not trusted by browsers.", check="ssl_labs"))

            # HSTS max-age
            sts = details.get("hstsPolicy") or {}
            if sts.get("status") == "present" and sts.get("maxAge", 0) < 15_552_000:
                vulns.append(_vuln("HSTS max-age too short", "medium",
                                   f"HSTS max-age={sts['maxAge']}s — should be ≥ 15552000 (6 months).",
                                   check="ssl_labs"))

        meta["ssllabs_grade"]  = "/".join(grades) or "N/A"
        meta["ssllabs_status"] = "READY"
        logger.info("SSL Labs | host=%s | grade=%s", host, meta["ssllabs_grade"])

    except Exception as exc:
        meta["ssllabs_error"] = str(exc)
        logger.debug("SSL Labs error: %s", exc)

    return vulns, meta


def _api_observatory(host: str) -> tuple[list[dict], dict]:
    """
    Mozilla HTTP Observatory v2 — security header grading.
    New v2 API is synchronous (no polling).
    https://observatory.mozilla.org/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    sess = _make_session()

    def _try_v2() -> dict | None:
        r = sess.post(
            f"https://observatory-api.mdn.mozilla.net/api/v2/analyze?host={host}",
            timeout=_API_TO,
        )
        if r.status_code == 200:
            return r.json()
        return None

    def _try_v1() -> dict | None:
        r = sess.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": host},
            data={"hidden": "true", "rescan": "false"},
            timeout=_API_TO,
        )
        if r.status_code != 200:
            return None
        data   = r.json()
        waited = 0
        while data.get("state") not in ("FINISHED", "FAILED", "ABORTED") and waited < 60:
            time.sleep(5)
            waited += 5
            r    = sess.get("https://http-observatory.security.mozilla.org/api/v1/analyze",
                            params={"host": host}, timeout=_API_TO)
            data = r.json()
        return data

    try:
        data = _try_v2() or _try_v1()
        if not data:
            return vulns, {"observatory_error": "Both v1 and v2 unreachable"}

        grade = data.get("grade", "")
        score = int(data.get("score", 0))
        meta["observatory_grade"] = grade
        meta["observatory_score"] = score

        if grade and grade not in ("A+", "A"):
            sev = "high" if grade in ("D", "F") else "medium" if grade == "C" else "low"
            vulns.append(_vuln(
                f"Mozilla Observatory grade: {grade} (score {score}/100)",
                sev,
                f"Security header configuration weak. Grade {grade}, score {score}/100.",
                evidence=f"https://observatory.mozilla.org/analyze/{host}",
                remediation="Review the full report at observatory.mozilla.org for exact fixes.",
                check="observatory",
            ))
        logger.info("Observatory | host=%s grade=%s score=%d", host, grade, score)

    except Exception as exc:
        meta["observatory_error"] = str(exc)
        logger.debug("Observatory error: %s", exc)

    return vulns, meta


def _api_shodan(ip: str | None) -> tuple[list[dict], dict]:
    """
    Shodan InternetDB — free IP intelligence (no key).
    Returns CVEs, open ports, hostnames, tags.
    https://internetdb.shodan.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=_API_TO)
        if r.status_code == 404:
            return vulns, {"shodan_note": "IP not indexed"}
        if r.status_code != 200:
            return vulns, {"shodan_error": f"HTTP {r.status_code}"}

        data  = r.json()
        ports = data.get("ports", [])
        cves  = data.get("vulns", [])
        tags  = data.get("tags", [])
        meta.update({"shodan_ports": ports, "shodan_cves": cves, "shodan_tags": tags})

        risky = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 1433, 1521, 11211}
        for p in ports:
            if p in risky:
                vulns.append(_vuln(
                    f"Shodan: risky port {p} exposed on {ip}",
                    "high",
                    f"Port {p} is publicly reachable per Shodan internet-wide scan.",
                    evidence=f"Shodan InternetDB: {ip} — port {p}",
                    remediation="Firewall this port if not required publicly.",
                    check="shodan",
                ))

        for cve_id in cves[:10]:
            vulns.append(_vuln(
                f"Shodan: known CVE on {ip} — {cve_id}",
                "high",
                f"Shodan has indexed {cve_id} as affecting {ip}.",
                evidence=f"Shodan InternetDB: {ip}",
                remediation=f"Patch: https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_ids=[cve_id], check="shodan",
            ))

        tag_map = {
            "malware":     ("critical", "Shodan: host tagged as malware distribution"),
            "self-signed": ("medium",   "Shodan: self-signed certificate detected"),
            "tor":         ("medium",   "Shodan: Tor exit node"),
            "honeypot":    ("info",     "Shodan: possible honeypot"),
        }
        for tag in tags:
            if tag.lower() in tag_map:
                sev, msg = tag_map[tag.lower()]
                vulns.append(_vuln(msg, sev, f"Shodan tag '{tag}' on {ip}.", check="shodan"))

        logger.info("Shodan | ip=%s ports=%s cves=%d", ip, ports, len(cves))

    except Exception as exc:
        meta["shodan_error"] = str(exc)
        logger.debug("Shodan error: %s", exc)

    return vulns, meta


def _api_virustotal(url: str, ip: str | None) -> tuple[list[dict], dict]:
    """
    VirusTotal v3 — URL + IP reputation against 90+ security vendors.
    Free key: https://www.virustotal.com → My Account → API Key → VT_API_KEY
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return vulns, {"virustotal_note": "VT_API_KEY not set — skipped"}

    headers = {"x-apikey": key}
    sess    = _make_session()

    try:
        # URL check
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = sess.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                     headers=headers, timeout=_API_TO)
        if r.status_code == 200:
            attrs     = r.json().get("data", {}).get("attributes", {})
            stats     = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            meta.update({"vt_malicious": malicious, "vt_suspicious": suspicious, "vt_total": total})

            if malicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {malicious}/{total} vendors flagged URL as malicious",
                    "critical",
                    f"{malicious} security vendors flagged this URL. Categories: "
                    f"{list(attrs.get('categories', {}).values())[:3]}",
                    evidence=f"VirusTotal URL: malicious={malicious}/{total}",
                    check="virustotal",
                ))
            elif suspicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {suspicious}/{total} vendors flagged URL as suspicious",
                    "medium",
                    f"{suspicious} security vendors consider this URL suspicious.",
                    check="virustotal",
                ))

        # IP check
        if ip and not _is_private(ip):
            r2 = sess.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                          headers=headers, timeout=_API_TO)
            if r2.status_code == 200:
                stats2 = r2.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal2   = stats2.get("malicious", 0)
                meta["vt_ip_malicious"] = mal2
                if mal2 > 0:
                    vulns.append(_vuln(
                        f"VirusTotal: IP {ip} flagged by {mal2} vendors",
                        "high",
                        f"Server IP is on {mal2} security vendor blocklists.",
                        evidence=f"VirusTotal IP: {ip}",
                        check="virustotal",
                    ))
        logger.info("VirusTotal | url malicious=%s ip_malicious=%s",
                    meta.get("vt_malicious"), meta.get("vt_ip_malicious"))

    except Exception as exc:
        meta["virustotal_error"] = str(exc)
        logger.debug("VirusTotal error: %s", exc)

    return vulns, meta


def _api_abuseipdb(ip: str | None) -> tuple[list[dict], dict]:
    """
    AbuseIPDB v2 — IP abuse confidence score (1000 req/day free).
    https://www.abuseipdb.com → Account → API Key → ABUSEIPDB_KEY
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not key or not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            data    = r.json().get("data", {})
            score   = data.get("abuseConfidenceScore", 0)
            total   = data.get("totalReports", 0)
            country = data.get("countryCode", "")
            isp     = data.get("isp", "")
            meta.update({"abuseipdb_score": score, "abuseipdb_reports": total,
                         "abuseipdb_isp": isp, "abuseipdb_country": country})

            if score >= 75:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} abuse score {score}/100 — HIGH RISK",
                    "high",
                    f"IP reported {total} times in 90 days. Score {score}/100. ISP: {isp}.",
                    evidence=f"https://www.abuseipdb.com/check/{ip}",
                    check="abuseipdb",
                ))
            elif score >= 25:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} moderate abuse score {score}/100",
                    "medium",
                    f"IP has {total} abuse reports (score {score}/100). ISP: {isp}.",
                    check="abuseipdb",
                ))
        logger.info("AbuseIPDB | ip=%s score=%s", ip, meta.get("abuseipdb_score"))

    except Exception as exc:
        meta["abuseipdb_error"] = str(exc)
        logger.debug("AbuseIPDB error: %s", exc)

    return vulns, meta


def _api_google_safebrowsing(url: str) -> tuple[list[dict], dict]:
    """
    Google Safe Browsing API v4 — used by Chrome, Safari, Firefox.
    Detects malware, phishing, unwanted software, harmful apps.
    Free key (10k req/day):
      1. console.cloud.google.com → new project
      2. APIs & Services → Enable "Safe Browsing API"
      3. Credentials → Create API Key
      Set GOOGLE_SAFE_BROWSING_KEY in .env
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key:
        return vulns, {"gsb_note": "GOOGLE_SAFE_BROWSING_KEY not set — skipped"}

    try:
        body = {
            "client":     {"clientId": "securax-scanner", "clientVersion": "4.2"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body, timeout=_API_TO,
        )
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            meta["gsb_threats"] = len(matches)
            for m in matches:
                threat_type = m.get("threatType", "UNKNOWN")
                sev = "critical" if threat_type in ("MALWARE", "SOCIAL_ENGINEERING") else "high"
                vulns.append(_vuln(
                    f"Google Safe Browsing: {threat_type}",
                    sev,
                    f"URL flagged by Google Safe Browsing as {threat_type}. "
                    "This URL is blocked by Chrome, Firefox and Safari.",
                    evidence=f"GSB threat type: {threat_type}",
                    check="google_safebrowsing",
                ))
            logger.info("Google Safe Browsing | url=%s threats=%d", url, len(matches))

    except Exception as exc:
        meta["gsb_error"] = str(exc)
        logger.debug("Google Safe Browsing error: %s", exc)

    return vulns, meta


def _api_urlscan(url: str, host: str) -> tuple[list[dict], dict]:
    """
    URLScan.io — URL analysis with screenshot, redirect chain, verdict.
    Used by CERTs and SOC teams worldwide.
    Free key: https://urlscan.io/user/apikey → URLSCAN_API_KEY
    Without key: searches recent public scans for the domain.
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key  = os.environ.get("URLSCAN_API_KEY", "").strip()
    sess = _make_session()

    try:
        if key:
            # Submit new private scan
            r = sess.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "private"},
                timeout=_API_TO,
            )
            if r.status_code in (200, 201):
                scan_uuid = r.json().get("uuid", "")
                meta["urlscan_uuid"] = scan_uuid
                if scan_uuid:
                    # Poll for result
                    waited = 0
                    result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
                    while waited < _URLSCAN_MAX:
                        time.sleep(_URLSCAN_POLL)
                        waited += _URLSCAN_POLL
                        res = sess.get(result_url, headers={"API-Key": key}, timeout=_API_TO)
                        if res.status_code == 200:
                            data = res.json()
                            verdict = data.get("verdicts", {}).get("overall", {})
                            score   = verdict.get("score", 0)
                            mal     = verdict.get("malicious", False)
                            meta.update({"urlscan_score": score, "urlscan_malicious": mal})
                            if mal:
                                vulns.append(_vuln(
                                    "URLScan.io: URL flagged as malicious",
                                    "critical",
                                    f"URLScan.io verdict: malicious, score={score}. "
                                    f"Report: https://urlscan.io/result/{scan_uuid}/",
                                    evidence=f"URLScan score={score}",
                                    check="urlscan",
                                ))
                            elif score and score > 50:
                                vulns.append(_vuln(
                                    f"URLScan.io: suspicious score {score}/100",
                                    "medium",
                                    f"URLScan.io score={score}/100. "
                                    f"Report: https://urlscan.io/result/{scan_uuid}/",
                                    check="urlscan",
                                ))
                            break
                        elif res.status_code == 404:
                            continue
            return vulns, meta

        # No key: search recent public scans for this domain
        r = sess.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{host}", "sort": "date:desc", "size": "5"},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            results = r.json().get("results", [])
            for item in results:
                verdict = item.get("verdicts", {}).get("overall", {})
                if verdict.get("malicious"):
                    scan_id = item.get("_id", "")
                    vulns.append(_vuln(
                        "URLScan.io: recent scan flagged domain as malicious",
                        "critical",
                        f"A recent URLScan.io public scan found this domain malicious. "
                        f"Report: https://urlscan.io/result/{scan_id}/",
                        check="urlscan",
                    ))
                    break
            meta["urlscan_recent_scans"] = len(results)
        logger.info("URLScan.io | host=%s results=%s", host, meta.get("urlscan_recent_scans"))

    except Exception as exc:
        meta["urlscan_error"] = str(exc)
        logger.debug("URLScan error: %s", exc)

    return vulns, meta


def _api_urlhaus(url: str) -> tuple[list[dict], dict]:
    """
    URLhaus by abuse.ch — malware distribution URL database.
    Used by all major CERTs. Free, no key required.
    https://urlhaus.abuse.ch/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            data   = r.json()
            status = data.get("query_status", "")
            meta["urlhaus_status"] = status

            if status == "is_online":
                tags     = data.get("tags") or []
                payloads = data.get("payloads") or []
                vulns.append(_vuln(
                    "URLhaus: URL is a known ACTIVE malware distribution site",
                    "critical",
                    f"This URL is listed in URLhaus as an ACTIVE malware host. "
                    f"Tags: {tags}. Payloads: {len(payloads)}.",
                    evidence=f"URLhaus: {url}",
                    check="urlhaus",
                ))
            elif status == "offline":
                vulns.append(_vuln(
                    "URLhaus: URL was previously a malware distribution site (now offline)",
                    "high",
                    "This URL was flagged as a malware host by URLhaus. Currently offline.",
                    check="urlhaus",
                ))
        logger.info("URLhaus | url=%s status=%s", url, meta.get("urlhaus_status"))

    except Exception as exc:
        meta["urlhaus_error"] = str(exc)
        logger.debug("URLhaus error: %s", exc)

    return vulns, meta


def _api_greynoise(ip: str | None) -> tuple[list[dict], dict]:
    """
    GreyNoise Community API — separates internet noise from targeted attacks.
    noise=true → IP is a known scanner/attacker.
    riot=true  → IP is a known benign service (Google, Cloudflare, etc.).
    Free, no key required. https://viz.greynoise.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=_API_TO)
        if r.status_code == 200:
            data           = r.json()
            noise          = data.get("noise", False)
            riot           = data.get("riot", False)
            classification = data.get("classification", "")
            name           = data.get("name", "")
            meta.update({"greynoise_noise": noise, "greynoise_riot": riot,
                         "greynoise_class": classification, "greynoise_name": name})

            if noise and classification == "malicious":
                vulns.append(_vuln(
                    f"GreyNoise: {ip} is a known MALICIOUS internet scanner",
                    "critical",
                    f"GreyNoise classifies {ip} as malicious ({name}). "
                    "This IP is actively scanning the internet with malicious intent.",
                    evidence="GreyNoise: noise=True, classification=malicious",
                    check="greynoise",
                ))
            elif noise:
                vulns.append(_vuln(
                    f"GreyNoise: {ip} is a known internet scanner ({classification})",
                    "medium",
                    f"GreyNoise identifies {ip} as an active scanner ({name}). "
                    "Investigate whether this IP should be serving your web application.",
                    check="greynoise",
                ))
        elif r.status_code == 404:
            meta["greynoise_note"] = "IP not in GreyNoise dataset (not observed scanning)"
        logger.info("GreyNoise | ip=%s noise=%s riot=%s", ip,
                    meta.get("greynoise_noise"), meta.get("greynoise_riot"))

    except Exception as exc:
        meta["greynoise_error"] = str(exc)
        logger.debug("GreyNoise error: %s", exc)

    return vulns, meta


def _api_ipinfo(ip: str | None) -> tuple[list[dict], dict]:
    """
    IPinfo.io — IP context: org, ASN, country, hosting flag.
    Free up to 50 000 req/month, no key required.
    https://ipinfo.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        # IPINFO_TOKEN = free 50k/month; with paid token: full privacy/hosting data
        # Get token free at https://ipinfo.io/signup  → IPINFO_TOKEN in .env
        _token = os.environ.get("IPINFO_TOKEN", "").strip()
        _headers = {"Authorization": f"Bearer {_token}"} if _token else {}
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=_headers, timeout=_API_TO)
        if r.status_code == 200:
            data = r.json()
            org     = data.get("org", "")
            country = data.get("country", "")
            asn     = data.get("asn", {}).get("asn", "") if isinstance(data.get("asn"), dict) else ""
            hosting = data.get("hosting", False)
            vpn     = data.get("privacy", {}).get("vpn", False) if isinstance(data.get("privacy"), dict) else False
            tor     = data.get("privacy", {}).get("tor", False) if isinstance(data.get("privacy"), dict) else False
            meta.update({"ipinfo_org": org, "ipinfo_country": country,
                         "ipinfo_asn": asn, "ipinfo_hosting": hosting})

            if tor:
                vulns.append(_vuln(
                    f"IPinfo: {ip} is a TOR exit node",
                    "high",
                    "Server IP is identified as a Tor exit node — investigate.",
                    check="ipinfo",
                ))
            elif vpn:
                vulns.append(_vuln(
                    f"IPinfo: {ip} is a VPN/proxy endpoint",
                    "medium",
                    "Server IP is identified as a VPN or anonymous proxy.",
                    check="ipinfo",
                ))
        logger.info("IPinfo | ip=%s org=%s country=%s", ip,
                    meta.get("ipinfo_org"), meta.get("ipinfo_country"))

    except Exception as exc:
        meta["ipinfo_error"] = str(exc)
        logger.debug("IPinfo error: %s", exc)

    return vulns, meta


def _api_crtsh(host: str) -> tuple[list[dict], dict]:
    """
    crt.sh — Certificate Transparency logs.
    Discovers subdomains registered in public SSL certificates.
    Free, no key required. https://crt.sh/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    try:
        _crt_sess = _make_session()   # retries help — crt.sh is often slow
        r = _crt_sess.get(
            "https://crt.sh/",
            params={"q": f"%.{host}", "output": "json"},
            timeout=20,
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return vulns, meta

        seen: set[str] = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name and host in name and name != host:
                    seen.add(name)

        subs = sorted(seen)
        meta["subdomains"] = subs

        if subs:
            vulns.append(_vuln(
                f"crt.sh: {len(subs)} subdomains discovered for {host}",
                "info",
                f"Certificate Transparency logs reveal {len(subs)} public subdomains. "
                "Each represents potential attack surface to review.",
                evidence=", ".join(subs[:20]) + ("…" if len(subs) > 20 else ""),
                remediation="Audit all subdomains — verify each is intentionally public and secured.",
                check="attack_surface",
            ))
        logger.info("crt.sh | host=%s subdomains=%d", host, len(subs))

    except Exception as exc:
        meta["crtsh_error"] = str(exc)
        logger.debug("crt.sh error: %s", exc)

    return vulns, meta


def _api_dns_security(host: str) -> tuple[list[dict], dict]:
    """
    DNS security checks via Google DNS-over-HTTPS.
    Verifies SPF and DMARC records — no extra packages required.
    """
    vulns: list[dict] = []
    meta:  dict       = {}

    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _doh(name: str, rtype: str) -> list[str]:
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": name, "type": rtype},
                timeout=8,
            )
            if r.status_code == 200:
                return [a.get("data", "") for a in r.json().get("Answer", [])
                        if a.get("type") == 16]  # TXT = 16
        except Exception:
            pass
        return []

    try:
        # SPF
        txt_records = _doh(domain, "TXT")
        spf_records = [t for t in txt_records if "v=spf1" in t.lower()]
        meta["dns_spf"] = spf_records[0] if spf_records else None

        if not spf_records:
            vulns.append(_vuln(
                f"No SPF record on {domain}",
                "medium",
                "Missing SPF (Sender Policy Framework) record allows email spoofing. "
                "Attackers can send emails pretending to be from your domain.",
                remediation='Add TXT record: "v=spf1 include:your-mail-provider.com ~all"',
                check="dns_security",
            ))
        elif len(spf_records) > 1:
            vulns.append(_vuln(
                f"Multiple SPF records on {domain}",
                "medium",
                "Multiple SPF records is invalid per RFC 7208 — only one is allowed.",
                check="dns_security",
            ))

        # DMARC
        dmarc_records = _doh(f"_dmarc.{domain}", "TXT")
        dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), None)
        meta["dns_dmarc"] = dmarc

        if not dmarc:
            vulns.append(_vuln(
                f"No DMARC record on {domain}",
                "medium",
                "Missing DMARC record. Without DMARC, email spoofing and phishing "
                "using your domain cannot be detected or blocked.",
                remediation=f'Add TXT record on _dmarc.{domain}: '
                            '"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
                check="dns_security",
            ))
        else:
            # Check DMARC policy strength
            if "p=none" in dmarc.lower():
                vulns.append(_vuln(
                    f"DMARC policy is 'none' (monitoring only) on {domain}",
                    "low",
                    "DMARC p=none only monitors — it does NOT block spoofed emails. "
                    "Upgrade to p=quarantine or p=reject.",
                    check="dns_security",
                ))

        logger.info("DNS security | domain=%s spf=%s dmarc=%s",
                    domain, bool(spf_records), bool(dmarc))

    except Exception as exc:
        meta["dns_error"] = str(exc)
        logger.debug("DNS security error: %s", exc)

    return vulns, meta


# ─────────────────────────────────────────────────────────────────────────────
# Local passive checks  (return list[dict])
# ─────────────────────────────────────────────────────────────────────────────

