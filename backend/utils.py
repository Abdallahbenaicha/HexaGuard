"""SecuraX — shared utilities and decorators used across blueprints."""

import io
import ipaddress
import logging
import os
import re
import socket
import threading
import time
import zipfile
from functools import wraps

from flask import jsonify, request
from flask_login import current_user, login_required

from database import get_locked_target, log_event, get_user_by_id

logger = logging.getLogger(__name__)

# ── Simple in-memory API response cache ───────────────────────────────────────

_cache_store: dict[str, tuple[object, float]] = {}
_cache_lock = threading.Lock()


def cache_response(ttl: int = 30):
    """Cache a GET endpoint's JSON response for `ttl` seconds per user.

    Only caches 200 responses.  Key is (user_id, path, query_string).
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method != "GET":
                return f(*args, **kwargs)
            uid = getattr(current_user, "id", "anon")
            key = f"{uid}:{request.path}:{request.query_string.decode()}"
            now = time.monotonic()
            with _cache_lock:
                hit = _cache_store.get(key)
                if hit and (now - hit[1]) < ttl:
                    return hit[0]
            result = f(*args, **kwargs)
            # Only cache successful JSON responses
            try:
                status = result[1] if isinstance(result, tuple) else 200
                if status == 200:
                    with _cache_lock:
                        _cache_store[key] = (result, now)
            except Exception:
                pass
            return result
        return wrapper
    return decorator


def invalidate_cache_for(user_id: int) -> None:
    """Clear all cached responses for a given user."""
    prefix = f"{user_id}:"
    with _cache_lock:
        stale = [k for k in _cache_store if k.startswith(prefix)]
        for k in stale:
            del _cache_store[k]

# ── Regex ──────────────────────────────────────────────────────────────────────
_UUID_RE = re.compile(r"^[0-9a-f]{32}$")

# ── Upload validation ──────────────────────────────────────────────────────────
_BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".dll",
    ".so", ".dylib", ".bin", ".msi", ".com", ".scr", ".pif",
}
_MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB uncompressed cap (zip bomb guard)


def validate_upload(file_storage, allowed_extensions: set) -> tuple:
    """Return (ok, error_message). Validates extension, size, and zip-bomb."""
    if not file_storage or not file_storage.filename:
        return False, "لم يتم رفع ملف."

    name = file_storage.filename.lower()
    ext  = os.path.splitext(name)[1]

    if ext in _BLOCKED_EXTENSIONS:
        return False, f"نوع الملف '{ext}' محظور لأسباب أمنية."
    if ext not in allowed_extensions:
        return False, f"الامتداد '{ext}' غير مسموح. المسموح: {', '.join(sorted(allowed_extensions))}"

    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > 10 * 1024 * 1024:
        return False, "حجم الملف يتجاوز الحد المسموح (10 MB)."

    if ext == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(file_storage.read()), "r") as zf:
                total = sum(i.file_size for i in zf.infolist())
                if total > _MAX_ZIP_UNCOMPRESSED:
                    return False, "الملف المضغوط يحتوي على بيانات كبيرة جداً (zip bomb محتمل)."
            file_storage.seek(0)
        except zipfile.BadZipFile:
            return False, "الملف ليس ملف ZIP صالحاً."

    return True, ""


# ── Decorators ─────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            # Admin always has all permissions
            if current_user.role == "admin":
                return f(*args, **kwargs)
            if not current_user.has_permission(permission):
                logger.warning(
                    "access denied | user=%s | permission=%s | path=%s",
                    current_user.username, permission, request.path,
                )
                log_event(
                    "access_denied", current_user.username, current_user.id,
                    category="security", resource=request.path,
                    ip_address=request.remote_addr, status="denied",
                    details=f"Missing permission: {permission}",
                )
                return jsonify({"error": "صلاحية غير كافية."}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Scanner permission guard ───────────────────────────────────────────────────

# Canonical slug → human label (used in error messages)
SCANNER_LABELS: dict[str, str] = {
    "web":       "Web Application Scan",
    "ssl":       "SSL/TLS Audit",
    "network":   "Network Recon",
    "dast":      "Dynamic Analysis (DAST)",
    "code":      "Code Audit (SAST)",
    "config":    "Config Audit",
    "server":    "Server Audit",
    "deps":      "Dependency Check",
    "docker":    "Docker Security",
    "dns":       "DNS & Email Security",
    "wordpress": "WordPress Audit",
}


def require_scanner(slug: str):
    """Enforce scanner-level access control.

    Admin: always allowed.
    User with allowed_scanners=None (legacy/unrestricted): allowed.
    User with allowed_scanners=[...]: only if slug is in the list.
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role == "admin":
                return f(*args, **kwargs)
            scanners = getattr(current_user, "allowed_scanners", None)
            if scanners is not None and slug not in scanners:
                label = SCANNER_LABELS.get(slug, slug)
                log_event(
                    "scanner_forbidden", current_user.username, current_user.id,
                    category="security", resource=slug, status="denied",
                    ip_address=request.remote_addr,
                    details=f"Scanner '{slug}' not in user's subscription",
                )
                return jsonify({
                    "error": f"ليس لديك صلاحية استخدام «{label}». تواصل مع المدير لتفعيل هذا الفاحص.",
                    "scanner_forbidden": True,
                    "scanner_slug": slug,
                }), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── SSRF Protection ───────────────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC-1918
    ipaddress.ip_network("172.16.0.0/12"),   # RFC-1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC-1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (AWS metadata)
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]

# Loopback-only networks — used by ALLOW_LOCAL_LAB_TARGETS (127.0.0.0/8 only).
_LOOPBACK_ONLY_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

_BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP/Azure metadata endpoint
}

# Metadata endpoints always blocked regardless of any lab flag.
_METADATA_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
}

_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("fe80::/10"),
]


def _is_loopback_only(ip_str: str) -> bool:
    """Return True iff ip_str is in the 127.0.0.0/8 or ::1 range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _LOOPBACK_ONLY_NETWORKS)
    except ValueError:
        return False


def _is_metadata(host_or_ip: str) -> bool:
    """Return True if the host is a known cloud-metadata endpoint."""
    if host_or_ip in _METADATA_HOSTNAMES:
        return True
    try:
        addr = ipaddress.ip_address(host_or_ip)
        return any(addr in net for net in _METADATA_NETWORKS)
    except ValueError:
        return False


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_env_truthy(var_name: str, default: str = "0") -> bool:
    """Return True if the environment variable has a truthy value ('1', 'true', 'yes', 'on')."""
    val = os.environ.get(var_name, default).strip().lower()
    return val in ("1", "true", "yes", "on")


import urllib.parse


def _extract_target_host(raw_target: str) -> str:
    """Extract clean hostname or IP string handling IPv6 brackets and scheme prefix."""
    s = raw_target.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "http://" + s
    try:
        p = urllib.parse.urlsplit(s)
        host = (p.hostname or "").strip().lower()
        return host
    except Exception:
        stripped = re.sub(r"^https?://", "", raw_target.strip())
        return stripped.split("/")[0].split("?")[0].strip().lower()


def _resolve_target_ips(host: str) -> list:
    """Resolve and normalize host into concrete IP objects, including legacy hex/octal formats."""
    # 1. Standard IP literal (IPv4 or bracket-free IPv6)
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    # 2. Normalize legacy hex/octal/decimal IPv4 notation (e.g., 0x7f000001, 2130706433, 127.1)
    if re.match(r"^[\d\.xXa-fA-F]+$", host):
        try:
            raw_bytes = socket.inet_aton(host)
            normalized = socket.inet_ntoa(raw_bytes)
            return [ipaddress.ip_address(normalized)]
        except (OSError, ValueError):
            pass

    # 3. DNS resolution via getaddrinfo
    try:
        resolved = socket.getaddrinfo(host, None)
        ips = []
        for item in resolved:
            try:
                ips.append(ipaddress.ip_address(item[4][0]))
            except ValueError:
                pass
        return ips
    except Exception:
        return []


def check_ssrf(raw_target: str) -> tuple[bool, str]:
    """Return (is_safe, error_msg).

    Blocks scan targets that resolve to private / link-local / metadata IPs
    to prevent Server-Side Request Forgery attacks against internal infrastructure.

    When the environment variable ALLOW_LOCAL_LAB_TARGETS is set (accepts 'true', '1', 'yes'), loopback
    addresses (127.0.0.0/8 and ::1 only) are permitted so that local lab targets
    such as DVWA can be scanned during development.  RFC-1918 ranges and all
    cloud-metadata endpoints remain blocked unconditionally.
    """
    _allow_lab = is_env_truthy("ALLOW_LOCAL_LAB_TARGETS")

    host = _extract_target_host(raw_target)
    if not host:
        return False, "Empty target."

    # Metadata endpoints are always blocked — even in lab mode.
    if _is_metadata(host):
        return False, f"Target '{host}' is a metadata endpoint — always blocked."

    # Block other known dangerous hostnames directly
    if host in _BLOCKED_HOSTNAMES:
        return False, f"Target '{host}' is blocked for security reasons."

    # In lab mode: allow loopback literals (127.x.x.x or ::1) directly
    if _allow_lab and _is_loopback_only(host):
        return True, ""

    ips = _resolve_target_ips(host)
    if not ips:
        logger.warning("SSRF block: could not resolve %s", host)
        return False, f"Target '{host}' could not be resolved — request rejected."

    for addr in ips:
        if _is_metadata(str(addr)) or any(addr in net for net in _METADATA_NETWORKS):
            logger.warning("SSRF block: %s resolved to metadata IP %s", host, addr)
            return False, "Target resolves to a metadata endpoint — not allowed."

        if _allow_lab and (addr.is_loopback or _is_loopback_only(str(addr))):
            continue

        if (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
            or any(addr in net for net in _PRIVATE_NETWORKS)
        ):
            logger.warning("SSRF block: %s resolved to private IP %s", host, addr)
            return False, "Target resolves to a private/internal IP address — not allowed."

    return True, ""


# Hostnames/IPs that must ALWAYS be blocked even for network scanners
_ALWAYS_BLOCKED = {
    "localhost", "127.0.0.1", "0.0.0.0",  # nosec B104
    "169.254.169.254",       # AWS/GCP/Azure metadata
    "metadata.google.internal",
    "::1",
}

_LOOPBACK_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def check_ssrf_network(raw_target: str) -> tuple[bool, str]:
    """Lighter SSRF check for the network (nmap) scanner.

    Allows private RFC-1918 ranges so users can scan their own internal
    infrastructure. Still blocks loopback and cloud-metadata endpoints which
    are never a legitimate scan target.

    In development mode (FLASK_ENV=development), loopback is also allowed
    so developers can test against 127.0.0.1 locally.
    """
    import os as _os
    _is_dev = (
        _os.environ.get("FLASK_ENV", "production") == "development"
        or is_env_truthy("ALLOW_LOCAL_LAB_TARGETS")
    )

    host = _extract_target_host(raw_target)
    if not host:
        return False, "Empty target."

    # Cloud metadata endpoints are ALWAYS blocked regardless of environment
    if _is_metadata(host) or host in ("169.254.169.254", "metadata.google.internal"):
        return False, f"Target '{host}' is blocked for security reasons."

    ips = _resolve_target_ips(host)
    if not ips:
        if re.match(r"^[\d\.xXa-fA-F:]+$", host):
            return False, f"Target '{host}' is invalid."
        return True, ""

    for addr in ips:
        if _is_metadata(str(addr)) or any(addr in net for net in _METADATA_NETWORKS):
            return False, "Link-local metadata targets are not allowed."

        if not _is_dev and (addr.is_loopback or any(addr in net for net in _LOOPBACK_NETS)):
            return False, "Loopback targets are not allowed in production."

    return True, ""


# ── Target lock helpers ────────────────────────────────────────────────────────

def _normalize_target(raw: str) -> str:
    """Strip protocol / path / port → bare lowercase hostname or IP."""
    t = re.sub(r'^https?://', '', raw.strip())
    t = t.split('/')[0].split('?')[0].split(':')[0]
    return t.lower().strip()


def _check_target_lock(raw_target: str, *, network_scan: bool = False, user_id: int | None = None):
    """Enforce SSRF protection and admin-assigned target restriction.

    Returns (True, None) if allowed, (False, error_response) if blocked.
    network_scan=True uses the lighter SSRF check that allows RFC-1918 addresses.
    """
    from flask import has_request_context
    in_req = has_request_context()
    ip_addr = request.remote_addr if in_req else "127.0.0.1"

    # ── SSRF guard (applies to everyone including admin) ──────────────────
    ssrf_fn = check_ssrf_network if network_scan else check_ssrf
    safe, ssrf_err = ssrf_fn(raw_target)
    if not safe:
        log_event(
            "ssrf_blocked",
            getattr(current_user, "username", "scheduler") if in_req else "scheduler",
            getattr(current_user, "id", user_id or 0) if in_req else (user_id or 0),
            category="security", resource=raw_target, status="denied",
            ip_address=ip_addr, details=ssrf_err,
        )
        return False, (jsonify({"error": ssrf_err, "ssrf_blocked": True}), 403)

    uid = user_id if user_id is not None else getattr(current_user, "id", None)
    role = getattr(current_user, "role", "")
    if uid is not None and not role:
        user_rec = get_user_by_id(uid)
        role = user_rec.get("role", "") if user_rec else ""

    if role == "admin":
        return True, None

    if uid is None:
        return True, None

    locked = get_locked_target(uid)
    if locked is None:
        return True, None

    normalized = _normalize_target(raw_target)
    if locked == normalized:
        return True, None

    uname = getattr(current_user, "username", "scheduler") if in_req else "scheduler"
    log_event(
        "target_violation", uname, uid,
        category="security", resource=normalized, status="denied",
        details=f"Blocked: tried {normalized!r}, allowed target is {locked!r}",
        ip_address=ip_addr,
    )
    return False, (
        jsonify({
            "error": (
                f"Access denied. Your account is restricted to target '{locked}'. "
                "Contact an administrator to change your allowed target."
            ),
            "allowed_target": locked,
            "forbidden": True,
        }),
        403,
    )

