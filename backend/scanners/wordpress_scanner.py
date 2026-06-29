"""HexaGuard — WordPress Security Scanner.

Performs non-destructive, read-only HTTP probing of a WordPress installation.
Uses only the already-installed `requests` library — no extra dependencies.

Checks performed:
  • WordPress detection (is the site actually WordPress?)
  • WordPress version disclosure (readme.html, meta generator)
  • User enumeration via REST API (/wp-json/wp/v2/users)
  • xmlrpc.php exposed (brute-force / SSRF vector)
  • /wp-admin/ login page accessible
  • Debug log exposed (/wp-content/debug.log)
  • wp-cron.php DoS vector
  • /wp-includes/ directory listing
  • /wp-config.php accessible (should always return 403/404)
  • Default admin username 'admin'
  • REST API user enumeration enabled
  • WordPress login without 2FA hint (informational)
  • Security headers: X-Frame-Options, X-Content-Type-Options, CSP
  • HTTP → HTTPS redirect
  • Outdated WordPress version (vs known-good version list)
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_UA      = "Mozilla/5.0 (compatible; HexaGuard-Scanner/2.0)"
_HEADERS = {"User-Agent": _UA}

# Known WP versions that are EOL / critically vulnerable
_EOL_VERSIONS: set[str] = {
    "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6",
    "4.7", "4.7.0", "4.7.1",  # auth bypass
    "4.8", "4.9", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5",
    "5.6", "5.7", "5.8", "5.9", "6.0", "6.1",
}

_SESSION = requests.Session()
_SESSION.headers.update(_HEADERS)


def _vuln(title: str, severity: str, description: str,
          recommendation: str, detail: str = "") -> dict:
    return {
        "title":          title,
        "severity":       severity,
        "description":    description,
        "recommendation": recommendation,
        "detail":         detail,
    }


def _normalize_url(target: str) -> str:
    """Ensure target has a scheme."""
    t = target.strip().rstrip("/")
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _get(url: str, **kwargs) -> requests.Response | None:
    try:
        return _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True, **kwargs)
    except Exception as exc:
        logger.debug("GET %s failed: %s", url, exc)
        return None


def _detect_wordpress(base: str) -> tuple[bool, str | None]:
    """Return (is_wordpress, version_or_None)."""
    r = _get(base)
    if r is None:
        return False, None

    body = r.text
    is_wp = False
    version = None

    # Generator meta tag
    m = re.search(r'<meta name=["\']generator["\'] content=["\']WordPress ([0-9.]+)', body, re.I)
    if m:
        is_wp = True
        version = m.group(1)

    # wp-content or wp-includes in HTML
    if re.search(r"wp-content|wp-includes", body, re.I):
        is_wp = True

    # readme.html
    if not version:
        r2 = _get(urljoin(base + "/", "readme.html"))
        if r2 and r2.status_code == 200:
            m2 = re.search(r"Version\s+([0-9.]+)", r2.text, re.I)
            if m2:
                is_wp = True
                version = m2.group(1)

    return is_wp, version


def _check_version(base: str, version: str | None) -> list:
    vulns: list[dict] = []
    if version is None:
        vulns.append(_vuln(
            "WordPress version not detected",
            "info",
            "Could not determine the WordPress version. This may mean version disclosure is disabled (good) "
            "or the scanner could not access readme.html.",
            "Ensure readme.html and the generator meta tag are removed to prevent version disclosure.",
        ))
        return vulns

    vulns.append(_vuln(
        f"WordPress version disclosed: {version}",
        "medium",
        f"The WordPress version ({version}) is publicly visible via readme.html or meta generator tag.",
        "Delete or restrict access to readme.html, and remove the generator meta tag via functions.php:\n"
        "  remove_action('wp_head', 'wp_generator');",
        detail=f"Detected version: {version}",
    ))

    if any(version.startswith(eol) for eol in _EOL_VERSIONS):
        vulns.append(_vuln(
            f"WordPress {version} is outdated / End-of-Life",
            "critical",
            f"WordPress {version} has known security vulnerabilities and is no longer receiving security patches.",
            "Update to the latest stable WordPress version immediately from wp-admin → Dashboard → Updates.",
            detail=f"Detected version: {version}",
        ))

    return vulns


def _check_xmlrpc(base: str) -> list:
    vulns: list[dict] = []
    r = _get(urljoin(base + "/", "xmlrpc.php"))
    if r and r.status_code == 200:
        vulns.append(_vuln(
            "xmlrpc.php is accessible",
            "high",
            "xmlrpc.php is enabled and publicly accessible. It can be used for credential brute-force, "
            "SSRF attacks, and DDoS amplification via the multicall method.",
            "Disable XML-RPC if not required:\n"
            "  1. Add to .htaccess: <Files xmlrpc.php>\\n    deny from all\\n</Files>\n"
            "  2. Or use a plugin like 'Disable XML-RPC'.",
        ))
    return vulns


def _check_user_enum(base: str) -> tuple[list, list]:
    vulns: list[dict] = []
    users_found: list = []

    # REST API enumeration
    r = _get(urljoin(base + "/", "wp-json/wp/v2/users"))
    if r and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                users_found = [u.get("slug", u.get("name", "?")) for u in data[:10]]
                vulns.append(_vuln(
                    "WordPress user list exposed via REST API",
                    "high",
                    f"The REST API endpoint /wp-json/wp/v2/users returned {len(data)} user(s): "
                    f"{', '.join(users_found)}. This allows attackers to enumerate usernames for brute-force.",
                    "Add to functions.php:\n"
                    "  add_filter('rest_endpoints', function($endpoints) {\n"
                    "    if (!is_user_logged_in()) {\n"
                    "      unset($endpoints['/wp/v2/users']);\n"
                    "      unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);\n"
                    "    }\n"
                    "    return $endpoints;\n"
                    "  });",
                    detail=f"Users: {', '.join(users_found)}",
                ))
                if "admin" in users_found:
                    vulns.append(_vuln(
                        "Default 'admin' username in use",
                        "high",
                        "The username 'admin' is present and publicly discoverable. "
                        "This is the first username attackers try in brute-force attacks.",
                        "Create a new administrator account with a unique username, then delete the 'admin' account.",
                        detail="Username 'admin' found in /wp-json/wp/v2/users",
                    ))
        except Exception:
            pass

    return vulns, users_found


def _check_debug_log(base: str) -> list:
    vulns: list[dict] = []
    r = _get(urljoin(base + "/", "wp-content/debug.log"))
    if r and r.status_code == 200 and len(r.text) > 10:
        vulns.append(_vuln(
            "WordPress debug.log publicly accessible",
            "critical",
            "The debug log file is publicly accessible and may contain file paths, database errors, "
            "plugin names, and other sensitive information that aids attackers.",
            "1. Disable WP_DEBUG in wp-config.php (set to false in production).\n"
            "2. Block access in .htaccess:\n"
            "   <Files debug.log>\\n    deny from all\\n</Files>",
        ))
    return vulns


def _check_wp_config(base: str) -> list:
    vulns: list[dict] = []
    r = _get(urljoin(base + "/", "wp-config.php"))
    if r and r.status_code == 200 and len(r.text) > 50:
        vulns.append(_vuln(
            "wp-config.php is publicly accessible",
            "critical",
            "wp-config.php contains database credentials and secret keys and is publicly downloadable. "
            "This is a catastrophic finding.",
            "Move wp-config.php one directory above the web root, or add to .htaccess:\n"
            "  <Files wp-config.php>\\n    deny from all\\n</Files>",
        ))
    return vulns


def _check_wpcron(base: str) -> list:
    vulns: list[dict] = []
    r = _get(urljoin(base + "/", "wp-cron.php"))
    if r and r.status_code == 200:
        vulns.append(_vuln(
            "wp-cron.php is publicly accessible (DoS vector)",
            "medium",
            "wp-cron.php can be triggered repeatedly by external requests, causing server resource exhaustion (DoS).",
            "Disable wp-cron.php from web access and use a real system cron instead:\n"
            "  In wp-config.php: define('DISABLE_WP_CRON', true);\n"
            "  Add a server cron: */5 * * * * wget -q -O - https://yourdomain.com/wp-cron.php?doing_wp_cron",
        ))
    return vulns


def _check_wp_admin(base: str) -> list:
    vulns: list[dict] = []
    r = _get(urljoin(base + "/", "wp-admin/"))
    if r and r.status_code == 200:
        # Check if login page is accessible (it should redirect to login.php)
        if "wp-login" in r.url or "wp-admin" in r.url:
            vulns.append(_vuln(
                "wp-admin login page publicly accessible",
                "info",
                "The WordPress admin login page is accessible without IP restrictions.",
                "Consider restricting access to /wp-admin/ to known IP addresses via .htaccess or server config. "
                "Ensure 2FA is enabled for all admin accounts (plugins: WP 2FA, Google Authenticator).",
            ))
    return vulns


def _check_directory_listing(base: str) -> list:
    vulns: list[dict] = []
    for path in ["wp-includes/", "wp-content/uploads/"]:
        r = _get(urljoin(base + "/", path))
        if r and r.status_code == 200 and "Index of" in r.text:
            vulns.append(_vuln(
                f"Directory listing enabled: /{path}",
                "medium",
                f"The directory /{path} has directory listing enabled, exposing file names and structure.",
                "Add to .htaccess:\n  Options -Indexes\nOr configure your web server to disable directory listing.",
                detail=path,
            ))
    return vulns


def _check_security_headers(base: str) -> list:
    vulns: list[dict] = []
    r = _get(base)
    if r is None:
        return vulns

    h = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("x-frame-options",          "X-Frame-Options missing (Clickjacking risk)", "medium",
         "Add header: X-Frame-Options: SAMEORIGIN"),
        ("x-content-type-options",   "X-Content-Type-Options missing (MIME sniffing risk)", "low",
         "Add header: X-Content-Type-Options: nosniff"),
        ("strict-transport-security","HSTS header missing", "medium",
         "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy",  "Content-Security-Policy header missing", "low",
         "Add a CSP header to restrict script/style sources and prevent XSS."),
    ]

    for header, title, sev, rec in checks:
        if header not in h:
            vulns.append(_vuln(title, sev, f"The HTTP response is missing the '{header}' header.", rec))

    return vulns


def _check_https_redirect(base: str) -> list:
    """Check that http:// redirects to https://."""
    vulns: list[dict] = []
    http_url = base.replace("https://", "http://", 1)
    try:
        r = requests.get(http_url, timeout=8, allow_redirects=False,
                         headers=_HEADERS)
        if r.status_code in (200, 301, 302):
            location = r.headers.get("Location", "")
            if not location.startswith("https://"):
                vulns.append(_vuln(
                    "HTTP does not redirect to HTTPS",
                    "high",
                    "The site is accessible over plain HTTP without enforcing an HTTPS redirect.",
                    "Configure a 301 redirect from http:// to https:// in your web server or .htaccess.",
                ))
    except Exception:
        pass
    return vulns


# ── Public entry point ─────────────────────────────────────────────────────────

def run_wordpress_scan(target: str) -> dict:
    """Scan a WordPress site and return a findings dict."""
    base = _normalize_url(target)
    t0   = time.perf_counter()

    all_vulns: list[dict] = []

    # Step 1 — detect WordPress
    is_wp, version = _detect_wordpress(base)
    if not is_wp:
        return {
            "scan_type":       "wordpress",
            "target":          base,
            "vulnerabilities": [],
            "counts":          {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "meta": {
                "wordpress_detected": False,
                "message": "No WordPress installation detected at this URL.",
                "scan_duration_s": round(time.perf_counter() - t0, 2),
            },
        }

    # Step 2 — run all checks
    all_vulns.extend(_check_version(base, version))
    all_vulns.extend(_check_xmlrpc(base))
    enum_vulns, users_found = _check_user_enum(base)
    all_vulns.extend(enum_vulns)
    all_vulns.extend(_check_debug_log(base))
    all_vulns.extend(_check_wp_config(base))
    all_vulns.extend(_check_wpcron(base))
    all_vulns.extend(_check_wp_admin(base))
    all_vulns.extend(_check_directory_listing(base))
    all_vulns.extend(_check_security_headers(base))
    all_vulns.extend(_check_https_redirect(base))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_vulns.sort(key=lambda x: sev_order.get(x["severity"], 99))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    return {
        "scan_type":       "wordpress",
        "target":          base,
        "vulnerabilities": all_vulns,
        "counts":          counts,
        "meta": {
            "wordpress_detected": True,
            "wordpress_version":  version,
            "users_found":        users_found,
            "scan_duration_s":    round(time.perf_counter() - t0, 2),
        },
    }
