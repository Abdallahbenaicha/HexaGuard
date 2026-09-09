from __future__ import annotations

__all__ = ['logger', 'logger', '_API_TO', '_PROBE_TO', '_SSLLABS_POLL', '_SSLLABS_MAX', '_URLSCAN_POLL', '_URLSCAN_MAX', '_MAX_WORKERS', 'REQUIRED_HEADERS', 'SENSITIVE_PATHS', 'DANGEROUS_METHODS', 'VULN_SERVER_RE', 'ERROR_PATTERNS', '_WAF_SIGS', '_TECH_SIGS']


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

# ── Timeouts ─────────────────────────────────────────────────────────────────
_API_TO       = 15
_PROBE_TO     = 5
_SSLLABS_POLL = 8
_SSLLABS_MAX  = 120
_URLSCAN_POLL = 8
_URLSCAN_MAX  = 90
_MAX_WORKERS  = 18   # 17 tasks total; extra slack so SSL Labs polling never starves others

# ── Required security headers ─────────────────────────────────────────────────
REQUIRED_HEADERS = [
    ("Strict-Transport-Security",  "high",   "HSTS missing — browser will not enforce HTTPS"),
    ("Content-Security-Policy",    "high",   "CSP missing — no XSS / injection protection policy"),
    ("X-Frame-Options",            "medium", "X-Frame-Options missing — clickjacking possible"),
    ("X-Content-Type-Options",     "medium", "MIME-sniffing protection missing"),
    ("Referrer-Policy",            "low",    "Referrer-Policy missing — URL may leak to third parties"),
    ("Permissions-Policy",         "low",    "Permissions-Policy missing — browser APIs unrestricted"),
    ("Cross-Origin-Opener-Policy", "low",    "COOP missing — cross-origin isolation not enforced"),
]

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # Critical
    ("/.git/config",              "critical", "Git config exposed — source code accessible"),
    ("/.git/HEAD",                "critical", "Git repo exposed — full history downloadable"),
    ("/.git/COMMIT_EDITMSG",      "critical", "Git commit messages exposed"),
    ("/.env",                     "critical", ".env exposed — API keys / DB passwords"),
    ("/.env.local",               "critical", ".env.local exposed"),
    ("/.env.production",          "critical", ".env.production exposed"),
    ("/.env.backup",              "critical", ".env.backup exposed"),
    ("/.htpasswd",                "critical", ".htpasswd password file exposed"),
    ("/wp-config.php",            "critical", "WordPress config exposed — DB credentials"),
    ("/.aws/credentials",         "critical", "AWS credentials file exposed"),
    ("/.npmrc",                   "critical", "npm credentials file exposed"),
    ("/backup.zip",               "critical", "Site backup archive downloadable"),
    ("/backup.sql",               "critical", "SQL backup downloadable"),
    ("/dump.sql",                 "critical", "Database dump downloadable"),
    ("/db.sql",                   "critical", "Database dump downloadable"),
    ("/config/database.php",      "critical", "Laravel database config exposed"),
    # High
    ("/phpinfo.php",              "high",     "phpinfo() exposed — full server config"),
    ("/server-status",            "high",     "Apache mod_status — live requests exposed"),
    ("/server-info",              "high",     "Apache mod_info — module config exposed"),
    ("/actuator",                 "high",     "Spring Boot Actuator base endpoint"),
    ("/actuator/env",             "critical", "Spring Boot /actuator/env — secrets exposed"),
    ("/actuator/heapdump",        "critical", "Spring Boot heap dump downloadable"),
    ("/actuator/beans",           "high",     "Spring Boot beans endpoint exposed"),
    ("/actuator/mappings",        "high",     "Spring Boot route mappings exposed"),
    ("/_profiler",                "high",     "Symfony Profiler exposed"),
    ("/storage/logs/laravel.log", "high",     "Laravel log — stack traces and secrets"),
    ("/web.config",               "high",     "IIS web.config exposed"),
    ("/Dockerfile",               "high",     "Dockerfile exposed — infrastructure info"),
    ("/docker-compose.yml",       "high",     "Docker Compose config exposed"),
    ("/.travis.yml",              "high",     "CI config exposed — may contain secrets"),
    ("/Jenkinsfile",              "high",     "Jenkins pipeline script exposed"),
    ("/wp-content/debug.log",     "high",     "WordPress debug log exposed"),
    # Medium
    ("/api/swagger.json",         "medium",   "Swagger/OpenAPI spec exposed"),
    ("/swagger.json",             "medium",   "Swagger spec exposed"),
    ("/openapi.json",             "medium",   "OpenAPI spec exposed"),
    ("/api/docs",                 "medium",   "API documentation exposed"),
    ("/graphql",                  "medium",   "GraphQL — verify introspection disabled"),
    ("/admin",                    "medium",   "Admin panel — verify authentication"),
    ("/wp-admin/",                "medium",   "WordPress admin panel"),
    ("/wp-json/wp/v2/users",      "medium",   "WordPress user enumeration endpoint"),
    ("/package.json",             "medium",   "package.json — dependency versions exposed"),
    ("/composer.json",            "medium",   "composer.json — PHP dependencies exposed"),
    # Low / Info
    ("/.DS_Store",                "low",      ".DS_Store — macOS directory structure leak"),
    ("/robots.txt",               "info",     "robots.txt — review for sensitive path hints"),
    ("/sitemap.xml",              "info",     "Sitemap exposed — full URL structure"),
    ("/.well-known/security.txt", "info",     "security.txt present"),
]

# ── Dangerous HTTP methods ────────────────────────────────────────────────────
DANGEROUS_METHODS = [
    ("TRACE",   "medium", "HTTP TRACE enabled — Cross-Site Tracing (XST) possible"),
    ("PUT",     "high",   "HTTP PUT enabled — arbitrary file upload possible"),
    ("DELETE",  "high",   "HTTP DELETE enabled — file deletion possible"),
    ("CONNECT", "medium", "HTTP CONNECT enabled — server usable as proxy"),
]

# ── Server CVE patterns ───────────────────────────────────────────────────────
VULN_SERVER_RE = [
    (r"Apache/2\.4\.(4[89]|50)\b",        "CVE-2021-41773", "Apache 2.4.49/50 Path Traversal + RCE",    "critical"),
    (r"Apache/2\.4\.(5[0-5])\b",          "CVE-2023-25690", "Apache < 2.4.56 Request Splitting",         "critical"),
    (r"Apache/2\.4\.([0-3]\d|4[0-8])\b",  "CVE-2022-22721", "Apache mod_sed buffer overflow",            "high"),
    (r"nginx/1\.(1[0-7]|[0-9])\.",        "CVE-2021-23017", "nginx DNS resolver buffer overwrite",       "high"),
    (r"nginx/1\.18\.[01]\b",              "CVE-2021-23017", "nginx 1.18 DNS resolver issue",             "medium"),
    (r"PHP/([0-7]\.|8\.[012]\.)",         "CVE-2024-4577",  "PHP CGI argument injection (< 8.3.8)",      "critical"),
    (r"OpenSSL/1\.[01]\.",                "CVE-2022-0778",  "OpenSSL 1.x infinite loop DoS",             "high"),
    (r"OpenSSL/3\.0\.[0-6]\b",           "CVE-2022-3786",  "OpenSSL 3.0.x buffer overrun",              "high"),
    (r"IIS/[0-7]\.",                      "CVE-2021-31166", "IIS HTTP stack RCE (< IIS 10)",             "critical"),
    (r"IIS/10\.0",                        "CVE-2022-21907", "IIS 10 HTTP Protocol Stack RCE",            "critical"),
]

# ── Error / info disclosure body patterns ────────────────────────────────────
ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL",                        "critical", "MySQL error — SQL Injection likely"),
    (r"Warning.*?mysql_",                          "critical", "PHP MySQL error — SQL Injection likely"),
    (r"ORA-\d{5}",                                "critical", "Oracle DB error exposed"),
    (r"Microsoft OLE DB.*?SQL Server",             "critical", "MSSQL error — SQL Injection likely"),
    (r"PostgreSQL.*?ERROR:\s",                     "critical", "PostgreSQL error exposed"),
    (r"Traceback \(most recent call last\)",       "high",     "Python traceback — stack trace disclosed"),
    (r"at [\w\.]+\([\w\.]+\.java:\d+\)",           "high",     "Java stack trace disclosed"),
    (r"<b>Warning</b>.*?on line \d+",              "medium",   "PHP warning in HTTP response"),
    (r"Fatal error.*?PHP",                         "high",     "PHP fatal error exposed"),
    (r"DEBUG\s*=\s*True",                          "medium",   "Django DEBUG=True in production"),
    (r"<title>(?:Django|Werkzeug).*?Error",        "high",     "Framework debug error page exposed"),
    (r"Caused by:.*?Exception",                    "high",     "Java exception chain disclosed"),
    (r"root:x:0:0:",                               "critical", "Possible /etc/passwd contents in response"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",  "critical", "Private key in HTTP response"),
    (r"AKIA[0-9A-Z]{16}",                          "critical", "AWS access key in HTTP response"),
    (r"sk_live_[0-9a-zA-Z]{24,}",                 "critical", "Stripe live API key in HTTP response"),
]

# ── WAF / CDN signatures ──────────────────────────────────────────────────────
_WAF_SIGS: dict[str, list[tuple[str, str | None]]] = {
    "Cloudflare":     [("server", "cloudflare"),    ("cf-ray", None)],
    "AWS CloudFront": [("x-amz-cf-id", None),       ("x-amz-cf-pop", None)],
    "AWS WAF":        [("x-amzn-requestid", None),  ("x-amzn-trace-id", None)],
    "Imperva":        [("x-iinfo", None),            ("x-cdn", "Incapsula")],
    "Akamai":         [("x-check-cacheable", None),  ("akamai-grn", None)],
    "Sucuri":         [("x-sucuri-id", None),        ("x-sucuri-cache", None)],
    "Azure CDN/WAF":  [("x-azure-ref", None),        ("x-ec-custom-error", None)],
    "F5 BIG-IP":      [("x-wa-info", None),          ("bigipserver", None)],
    "Fastly":         [("x-fastly-request-id", None),("fastly-debug-digest", None)],
    "Varnish":        [("x-varnish", None),          ("via", "varnish")],
    "ModSecurity":    [("x-modsecurity", None)],
}

# ── Technology fingerprints ───────────────────────────────────────────────────
_TECH_SIGS: dict[str, list[tuple[str, str]]] = {
    "WordPress":     [("header", r"x-pingback"), ("cookie", r"^wordpress_"), ("body", r"wp-content|wp-includes")],
    "Drupal":        [("header", r"x-generator.*drupal"), ("cookie", r"^SESS[a-f0-9]{32}")],
    "Joomla":        [("body", r"generator.*Joomla"), ("cookie", r"^joomla_")],
    "Laravel":       [("cookie", r"XSRF-TOKEN"), ("cookie", r"laravel_session")],
    "Django":        [("cookie", r"^csrftoken"), ("body", r"csrfmiddlewaretoken")],
    "Spring/Java":   [("cookie", r"JSESSIONID"), ("header", r"x-application-context")],
    "ASP.NET":       [("header", r"x-powered-by.*asp\.net"), ("cookie", r"ASP\.NET_SessionId")],
    "PHP":           [("header", r"x-powered-by.*php"), ("cookie", r"PHPSESSID")],
    "Express/Node":  [("header", r"x-powered-by.*express")],
    "Ruby on Rails": [("cookie", r"_\w+_session$")],
    "Next.js":       [("body", r"__NEXT_DATA__"), ("header", r"x-nextjs-cache")],
    "Nuxt.js":       [("body", r"__NUXT__")],
    "React":         [("body", r"data-reactroot|__react_fiber")],
    "Angular":       [("body", r"ng-version|angular\.min\.js")],
    "Vue.js":        [("body", r"__vue__|vue\.runtime\.min\.js")],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

