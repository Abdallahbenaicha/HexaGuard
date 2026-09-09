from __future__ import annotations

__all__ = ['logger', 'run_web_scan']


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
    from scanners.web.intel_apis import *
    from scanners.web.local_checks import *
except ImportError:
    from backend.scanners.web.constants import *
    from backend.scanners.web.utils import *
    from backend.scanners.web.intel_apis import *
    from backend.scanners.web.local_checks import *

def run_web_scan(
    target: str,
    cve_check: bool = True,
    ssl_check: bool = True,
    extra_headers: dict | None = None,
    rate_limit: int | None = None,
) -> dict:
    """
    Full passive web security scan — local checks + 11 external APIs in parallel.

    Args:
        target:        URL, domain, or IP. http/https added automatically if missing.
        cve_check:     If False, skip Shodan/VirusTotal/AbuseIPDB/GreyNoise reputation APIs.
        ssl_check:     If False, skip SSL Labs and direct SSL probe (faster for HTTP-only targets).
        extra_headers: Optional custom HTTP headers (Cookie, Authorization, User-Agent, etc.)
        rate_limit:    Optional rate limit (req/s) for throttling sensitive path probes.

    Returns:
        { "scan_type": "web", "vulnerabilities": [...], "meta": {...} }
    """
    import sys
    _mod = sys.modules.get("scanners.web_scanner") or sys.modules.get("backend.scanners.web_scanner")
    _session_factory = getattr(_mod, "_make_session", _make_session) if _mod else _make_session
    _tpe = getattr(_mod, "ThreadPoolExecutor", ThreadPoolExecutor) if _mod else ThreadPoolExecutor
    _as_comp = getattr(_mod, "as_completed", as_completed) if _mod else as_completed

    url    = _norm_url(target)
    parsed = urlparse(url)
    host   = parsed.hostname or target
    sess   = _session_factory(extra_headers)
    vulns: list[dict] = []
    meta:  dict       = {}

    logger.info("web_scan start | url=%s", url)

    # ── Step 1: Initial HTTP fetch ────────────────────────────────────────────
    resp = None
    try:
        resp = sess.get(url, timeout=14, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        vulns.append(_vuln("SSL/TLS error on initial request", "critical",
                           str(exc), check="ssl"))
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = sess.get(url, timeout=14, verify=False, allow_redirects=True)
        except requests.RequestException as exc2:
            raise RuntimeError(f"Cannot reach target: {exc2}") from exc2
    except requests.RequestException as exc:
        raise RuntimeError(f"Cannot reach target: {exc}") from exc

    # ── Step 2: Resolve IP ────────────────────────────────────────────────────
    ip = _resolve_ip(host)
    meta["resolved_ip"] = ip

    # ── Step 3: Instant local checks (no network, sequential) ─────────────────
    vulns += _local_headers(resp.headers)
    vulns += _local_server_disclosure(resp.headers)
    vulns += _local_cookies(resp)
    vulns += _local_response_body(resp)
    vulns += _local_waf(resp.headers)
    vulns += _local_tech(resp)

    # ── Step 4: All external API calls + network probes in parallel ───────────
    tasks: list[tuple] = [
        ("ssllabs",    _api_ssllabs,          (host,),                                     True,  ssl_check and parsed.scheme == "https"),
        ("observatory",_api_observatory,       (host,),                                     True,  True),
        ("shodan",     _api_shodan,            (ip,),                                       True,  cve_check),
        ("virustotal", _api_virustotal,        (url, ip),                                   True,  cve_check),
        ("abuseipdb",  _api_abuseipdb,         (ip,),                                       True,  cve_check),
        ("gsb",        _api_google_safebrowsing,(url,),                                     True,  True),
        ("urlscan",    _api_urlscan,           (url, host),                                 True,  cve_check),
        ("urlhaus",    _api_urlhaus,           (url,),                                      True,  cve_check),
        ("greynoise",  _api_greynoise,         (ip,),                                       True,  cve_check),
        ("ipinfo",     _api_ipinfo,            (ip,),                                       True,  True),
        ("crtsh",      _api_crtsh,             (host,),                                     True,  True),
        ("dns",        _api_dns_security,      (host,),                                     True,  True),
        ("methods",    _local_http_methods,    (url, extra_headers),                         False, True),
        ("paths",      _local_sensitive_paths, (url, extra_headers, rate_limit),           False, True),
        ("redirect",   _local_https_redirect,  (url, host, extra_headers),                  False, True),
        ("ssl_direct", _local_ssl_direct,      (host,),                                     False, ssl_check and parsed.scheme == "https"),
        ("cors",       _local_cors,            (url, dict(resp.headers), extra_headers),  False, True),
    ]

    with _tpe(max_workers=_MAX_WORKERS, thread_name_prefix="webscan") as pool:
        futures: dict = {}
        for name, fn, args, is_api, enabled in tasks:
            if not enabled:
                continue
            futures[pool.submit(fn, *args)] = (name, is_api)

        for fut in _as_comp(futures):
            name, is_api = futures[fut]
            try:
                result = fut.result()
                if is_api:
                    task_vulns, task_meta = result
                    vulns.extend(task_vulns)
                    meta.update(task_meta)
                else:
                    vulns.extend(result)
            except Exception as exc:
                logger.warning("webscan task '%s' raised: %s", name, exc)

    # ── Step 5: Deduplicate + sort ────────────────────────────────────────────
    seen:   set[str]   = set()
    unique: list[dict] = []
    for v in vulns:
        k = _dedup_key(v)
        if k not in seen:
            seen.add(k)
            unique.append(v)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda v: order.get(v.get("severity", "info"), 5))

    subdomains = meta.get("subdomains", [])
    apis_used  = [
        "SSL Labs", "Mozilla Observatory", "Shodan InternetDB",
        "VirusTotal", "AbuseIPDB", "URLhaus", "GreyNoise", "IPinfo",
        "URLScan.io", "crt.sh", "DNS-over-HTTPS",
    ]
    if os.environ.get("GOOGLE_SAFE_BROWSING_KEY"):
        apis_used.append("Google Safe Browsing")

    logger.info(
        "web_scan done | host=%s findings=%d ssl=%s obs=%s",
        host, len(unique),
        meta.get("ssllabs_grade", "N/A"),
        meta.get("observatory_grade", "N/A"),
    )

    return {
        "scan_type":       "web",
        "target":          target,
        "url":             resp.url,
        "status_code":     resp.status_code,
        "vulnerabilities": unique,
        "meta": {
            "scan_time":          datetime.now(timezone.utc).isoformat(),
            "host":               host,
            "resolved_ip":        ip,
            "findings_count":     len(unique),
            "ssl_grade":          meta.get("ssllabs_grade"),
            "observatory_grade":  meta.get("observatory_grade"),
            "observatory_score":  meta.get("observatory_score"),
            "shodan_ports":       meta.get("shodan_ports"),
            "shodan_cves":        meta.get("shodan_cves"),
            "vt_malicious":       meta.get("vt_malicious"),
            "abuseipdb_score":    meta.get("abuseipdb_score"),
            "greynoise_noise":    meta.get("greynoise_noise"),
            "greynoise_class":    meta.get("greynoise_class"),
            "ipinfo_org":         meta.get("ipinfo_org"),
            "ipinfo_country":     meta.get("ipinfo_country"),
            "urlhaus_status":     meta.get("urlhaus_status"),
            "gsb_threats":        meta.get("gsb_threats", 0),
            "dns_spf":            meta.get("dns_spf"),
            "dns_dmarc":          meta.get("dns_dmarc"),
            "subdomains":         subdomains,
            "subdomains_count":   len(subdomains),
            "apis_used":          apis_used,
        },
    }

