from __future__ import annotations

__all__ = ['logger', '_make_session', '_norm_url', '_resolve_ip', '_is_private', '_vuln', '_dedup_key', '_404_fingerprint', '_is_soft_404']


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
except ImportError:
    from backend.scanners.web.constants import *

def _make_session(extra_headers: dict | None = None) -> requests.Session:
    sess = requests.Session()
    # Ignore any ambient HTTP_PROXY/HTTPS_PROXY env vars the host platform
    # may inject — this scanner must always reach targets directly.
    sess.trust_env = False
    retry = Retry(
        total=2,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("https://", adapter)
    sess.mount("http://",  adapter)
    sess.headers["User-Agent"] = "SecuraX-Security-Scanner/4.2"
    if extra_headers:
        sess.headers.update(extra_headers)
    return sess


def _norm_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def _resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _is_private(ip: str) -> bool:
    try:
        a = ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def _vuln(
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
    remediation: str = "",
    cve_ids: list | None = None,
    check: str = "web",
) -> dict:
    v: dict = {"check": check, "title": title, "severity": severity, "description": description}
    if evidence:    v["evidence"]    = evidence
    if remediation: v["remediation"] = remediation
    if cve_ids:     v["cve_ids"]     = cve_ids
    return v


def _dedup_key(v: dict) -> str:
    raw = v.get("check", "") + "|" + re.sub(r"https?://\S+", "URL", v.get("title", ""))[:80]
    return hashlib.md5(raw.lower().encode(), usedforsecurity=False).hexdigest()


def _404_fingerprint(base_url: str, sess: requests.Session) -> tuple[int, str]:
    """Probe a nonexistent path to fingerprint soft-404 responses."""
    probe = f"/securax-probe-{os.urandom(4).hex()}-notfound.html"
    try:
        r = sess.get(f"{base_url}{probe}", timeout=_PROBE_TO,
                     allow_redirects=False, verify=False)
        return len(r.content), hashlib.md5(r.content[:512], usedforsecurity=False).hexdigest()
    except Exception:
        return 0, ""


def _is_soft_404(content: bytes, fp: tuple[int, str]) -> bool:
    fp_len, fp_hash = fp
    if fp_len == 0:
        return False
    h = hashlib.md5(content[:512], usedforsecurity=False).hexdigest()
    if h == fp_hash:
        return True
    # within 8% of 404 size → very likely a custom 404 page
    if fp_len > 0 and abs(len(content) - fp_len) / max(fp_len, 1) < 0.08:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# External API checks  (each returns  (list[dict], dict))
# ─────────────────────────────────────────────────────────────────────────────

