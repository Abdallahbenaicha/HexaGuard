"""SecuraX — Bug Bounty policy enforcement and targets management.

Provides:
  - _enforce_bounty_policy_gate(data, user_id, username)  → (ok, error_response)
      Server-side guardian called by scan bridges.
      Feature Flag gated: if ENABLE_LIVE_BOUNTY_SCANNING is not 'true', rejects
      any scan carrying bounty_context with HTTP 403 (BOUNTY_SCANNING_DISABLED).

  - _bounty_engine_params(policy_snapshot)
      Reads policy signals and returns enforced (rate_limit, threads).

  - HTTP Endpoints (registered on bounty_bp):
      POST /api/bounty/verify-policy
      GET  /api/admin/bounty-targets
      POST /api/admin/bounty-targets/refresh
      GET  /api/admin/bounty-targets/stats
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import ipaddress
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from database import log_event
from extensions import csrf, limiter
from utils import admin_required

logger = logging.getLogger(__name__)

bounty_bp = Blueprint("bounty", __name__)

# ════════════════════════════════════════════════════════════════════════════
#  BUG BOUNTY TARGETS CACHING & FETCHING (arkadiyt/bounty-targets-data)
# ════════════════════════════════════════════════════════════════════════════

_BB_CACHE_TTL   = 3600          # 1 hour
_BB_CACHE_LOCK  = threading.Lock()
_BB_CACHE: dict = {}            # platform → {"data": [...], "ts": float}
_BB_INFLIGHT: set = set()       # single-flight: platforms being fetched right now

_PLATFORM_URLS = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

# ── Scan-policy detection ────────────────────────────────────────────────────
_ALLOW_TERMS = [
    "automated scanning allowed", "automated scanning is allowed",
    "automated testing allowed", "automated tools allowed",
    "automated scanning is permitted", "automated scanning permitted",
    "feel free to use automated", "scanners are allowed",
    "you may use automated", "automated tools are fine",
    "burp suite is allowed", "zap is allowed",
]

_BLOCK_TERMS = [
    "no automated scanning", "no automated testing",
    "do not use automated", "do not run automated",
    "automated scanning is prohibited", "automated scanning prohibited",
    "automated tools are not allowed", "automated tools not permitted",
    "manual testing only", "manual only",
    "no scanners", "scanners not allowed", "scanners are not permitted",
    "no vulnerability scanner", "no automated vulnerability",
    "without prior permission", "without written permission",
    "please do not run",
]

_RESTRICT_TERMS = [
    "rate limit", "rate-limit", "rate limiting",
    "no dos", "no denial of service", "no brute force", "no bruteforce",
    "no aggressive", "do not perform dos",
    "avoid high volume", "low and slow",
    "authentication required", "auth required",
    "production only", "no testing on production",
]


def _analyse_policy(text: str | None) -> dict:
    """Return a rich scan-policy dict instead of a binary bool.

    Returns:
        {
            "status":     "ALLOWED" | "RESTRICTED" | "UNKNOWN",
            "confidence": 0 .. 100,
            "signals":    [ "matched phrase 1", ... ]
        }
    """
    if not text:
        return {"status": "UNKNOWN", "confidence": 0,
                "signals": ["No policy or instruction text provided by program"]}

    t = text.lower()
    signals: list[str] = []

    allow_hits    = [term for term in _ALLOW_TERMS    if term in t]
    block_hits    = [term for term in _BLOCK_TERMS    if term in t]
    restrict_hits = [term for term in _RESTRICT_TERMS if term in t]

    for term in allow_hits:
        signals.append(f"+ Explicit permission: \"{term}\"")
    for term in block_hits:
        signals.append(f"- Explicit restriction: \"{term}\"")
    for term in restrict_hits:
        signals.append(f"⚠ Operational limit: \"{term}\"")

    if block_hits and not allow_hits:
        return {"status": "RESTRICTED", "confidence": 85, "signals": signals}

    if allow_hits and not block_hits:
        conf = 90 if not restrict_hits else 70
        stat = "ALLOWED" if not restrict_hits else "RESTRICTED"
        return {"status": stat, "confidence": conf, "signals": signals}

    if allow_hits and block_hits:
        return {"status": "RESTRICTED", "confidence": 50,
                "signals": signals + ["Contradictory signals — manual review required"]}

    if restrict_hits:
        return {"status": "RESTRICTED", "confidence": 40, "signals": signals}

    return {"status": "UNKNOWN", "confidence": 20,
            "signals": ["No automation-related terms found in instructions"]}


_WEB_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN", "WEB_APPLICATION"}


def _fetch_platform(platform: str) -> list:
    """Fetch and parse one platform JSON, cached for TTL seconds."""
    with _BB_CACHE_LOCK:
        cached = _BB_CACHE.get(platform)
        if cached and (time.time() - cached["ts"]) < _BB_CACHE_TTL:
            return cached["data"]
        if platform in _BB_INFLIGHT:
            return cached["data"] if cached else []
        _BB_INFLIGHT.add(platform)

    try:
        url = _PLATFORM_URLS.get(platform)
        if not url:
            return []
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "HexaGuard/1.0 (bug-bounty-browser)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            raw = json.loads(resp.read().decode())
        with _BB_CACHE_LOCK:
            _BB_CACHE[platform] = {"data": raw, "ts": time.time()}
        return raw
    except Exception as exc:
        logger.warning("bounty-targets: failed to fetch %s — %s", platform, exc)
        with _BB_CACHE_LOCK:
            cached = _BB_CACHE.get(platform)
        return cached["data"] if cached else []
    finally:
        with _BB_CACHE_LOCK:
            _BB_INFLIGHT.discard(platform)


def _normalise_hackerone(programs: list) -> list:
    out = []
    for prog in programs:
        if prog.get("submission_state") != "open":
            continue
        prog_policy = prog.get("policy", "") or ""
        for scope_item in prog.get("targets", {}).get("in_scope", []):
            asset_type = scope_item.get("asset_type", "")
            if asset_type not in _WEB_ASSET_TYPES:
                continue
            scope_instr = scope_item.get("instruction") or ""
            combined    = (scope_instr + " " + prog_policy).strip() or None
            policy      = _analyse_policy(combined)
            sev_raw = scope_item.get("max_severity") or ""
            max_sev = sev_raw.lower() if sev_raw else "unknown"
            out.append({
                "platform":         "hackerone",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("handle", ""),
                "program_url":      prog.get("url", ""),
                "website":          prog.get("website", ""),
                "asset":            scope_item.get("asset_identifier", ""),
                "asset_type":       asset_type,
                "max_severity":     max_sev,
                "eligible_bounty":  scope_item.get("eligible_for_bounty", False),
                "scan_policy":      policy,
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_instr,
                "managed":          prog.get("managed_program", False),
                "avg_response_h":   prog.get("average_time_to_first_program_response"),
            })
    return out


def _normalise_bugcrowd(programs: list) -> list:
    out = []
    for prog in programs:
        if not prog.get("targets"):
            continue
        prog_brief  = prog.get("brief", "") or ""
        prog_extra  = prog.get("target_groups_extra", "") or ""
        prog_policy = (prog_brief + " " + prog_extra).strip() or None
        rewards = prog.get("rewards", {}) or {}
        if rewards.get("critical"):
            prog_max_sev = "critical"
        elif rewards.get("high"):
            prog_max_sev = "high"
        elif rewards.get("medium"):
            prog_max_sev = "medium"
        else:
            prog_max_sev = "low"
        for scope_item in prog.get("targets", {}).get("in_scope", []):
            asset_type = scope_item.get("type", "")
            if asset_type.lower() not in {"website", "web application", "api", "wildcard"}:
                continue
            scope_desc  = scope_item.get("description") or ""
            combined    = (scope_desc + " " + (prog_policy or "")).strip() or None
            policy      = _analyse_policy(combined)
            out.append({
                "platform":         "bugcrowd",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("name", "").lower().replace(" ", "-"),
                "program_url":      prog.get("program_url", ""),
                "website":          scope_item.get("target", ""),
                "asset":            scope_item.get("target", ""),
                "asset_type":       "URL",
                "max_severity":     prog_max_sev,
                "eligible_bounty":  bool(prog.get("max_payout")),
                "scan_policy":      policy,
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_desc,
                "managed":          False,
                "avg_response_h":   None,
            })
    return out


def _normalise_yeswehack(programs: list) -> list:
    out = []
    for prog in programs:
        if not prog.get("scopes"):
            continue
        prog_policy_text = (prog.get("policy") or prog.get("description") or "").strip() or None
        reward_grid = prog.get("bounty_reward_range") or {}
        if reward_grid.get("critical"):
            prog_max_sev = "critical"
        elif reward_grid.get("high"):
            prog_max_sev = "high"
        elif reward_grid.get("medium"):
            prog_max_sev = "medium"
        elif prog.get("bounty"):
            prog_max_sev = "low"
        else:
            prog_max_sev = "unknown"
        for scope_item in prog.get("scopes", []):
            scope_type = scope_item.get("scope_type", "")
            if scope_type.lower() not in {"web-application", "api", "ip-address"}:
                continue
            scope_desc = scope_item.get("description") or ""
            combined   = (scope_desc + " " + (prog_policy_text or "")).strip() or None
            policy     = _analyse_policy(combined)
            out.append({
                "platform":         "yeswehack",
                "program_name":     prog.get("name", ""),
                "program_handle":   prog.get("slug", ""),
                "program_url":      f"https://yeswehack.com/programs/{prog.get('slug', '')}",
                "website":          scope_item.get("scope", ""),
                "asset":            scope_item.get("scope", ""),
                "asset_type":       "URL" if scope_type != "ip-address" else "CIDR",
                "max_severity":     prog_max_sev,
                "eligible_bounty":  prog.get("bounty", False),
                "scan_policy":      policy,
                "auto_scan_ok":     policy["status"] == "ALLOWED",
                "instruction":      scope_desc,
                "managed":          False,
                "avg_response_h":   None,
            })
    return out


_NORMALISERS = {
    "hackerone": (_fetch_platform, _normalise_hackerone),
    "bugcrowd":  (_fetch_platform, _normalise_bugcrowd),
    "yeswehack": (_fetch_platform, _normalise_yeswehack),
}


# ── Rate-limit signals ────────────────────────────────────────────────────────
_RATE_SIGNALS = frozenset([
    "rate limit", "rate-limit", "rate limiting",
    "no brute force", "no bruteforce",
    "no aggressive", "avoid high volume",
    "low and slow", "no dos", "no denial of service",
    "do not perform dos",
])

_RESTRICTED_RATE    = 5     # requests / second
_RESTRICTED_THREADS = 1     # concurrent threads

_PASSIVE_GUARD_MIN_CONFIDENCE = 80


def _get_bb_cache():
    """Return the live in-memory bounty cache and normalisers."""
    return _BB_CACHE, _NORMALISERS


def _extract_scan_domain(url_or_target: str) -> str:
    """Extract bare hostname from a URL or target string, lower-cased."""
    s = (url_or_target or "").strip().lower()
    s = re.sub(r'^https?://', '', s)
    s = s.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    return s.strip('.')


def _passive_bounty_guard(
    scan_domain: str,
) -> tuple[bool, dict | None]:
    """Layer-1 guard: check scan_domain against high-confidence restricted
    bounty assets cached from all platforms.
    """
    if not scan_domain:
        return True, None

    bb_cache, _ = _get_bb_cache()
    with _BB_CACHE_LOCK:
        cached_platforms = {
            plat: entry["data"]
            for plat, entry in bb_cache.items()
            if entry.get("data")
        }

    if not cached_platforms:
        return True, None

    for platform, targets in cached_platforms.items():
        for t in targets:
            policy = t.get("scan_policy") or {}
            status = policy.get("status")
            confidence = policy.get("confidence", 0)

            if status not in ("RESTRICTED", "UNKNOWN"):
                continue
            if confidence < _PASSIVE_GUARD_MIN_CONFIDENCE:
                continue

            asset = (t.get("asset") or "").strip().lower()
            if not asset:
                continue

            asset_domain = _extract_scan_domain(asset)

            if scan_domain == asset_domain:
                return False, {
                    "asset":          asset,
                    "platform":       platform,
                    "program_handle": t.get("program_handle", ""),
                    "program_name":   t.get("program_name", ""),
                    "status":         status,
                    "confidence":     confidence,
                    "signals":        policy.get("signals", []),
                    "match_type":     "exact",
                }

            if asset.startswith('*.'):
                wildcard_base = asset[2:]
                if scan_domain.endswith('.' + wildcard_base):
                    return False, {
                        "asset":          asset,
                        "platform":       platform,
                        "program_handle": t.get("program_handle", ""),
                        "program_name":   t.get("program_name", ""),
                        "status":         status,
                        "confidence":     confidence,
                        "signals":        policy.get("signals", []),
                        "match_type":     "wildcard_suffix",
                    }

    return True, None


def _bounty_engine_params(policy_snapshot: dict) -> tuple[int, int]:
    """Return (rate_limit, threads) based on policy signals."""
    signals_lower = " ".join(
        s.lower() for s in policy_snapshot.get("signals", [])
    )
    if any(sig in signals_lower for sig in _RATE_SIGNALS):
        return _RESTRICTED_RATE, _RESTRICTED_THREADS
    return 50, 3


def _enforce_bounty_policy_gate(
    data: dict,
    user_id: int,
    username: str,
) -> tuple[bool, object]:
    """Server-side bounty policy gate.

    If ENABLE_LIVE_BOUNTY_SCANNING is not active, rejects any scan with
    bounty_context with HTTP 403 (BOUNTY_SCANNING_DISABLED).
    """
    is_live_bounty_enabled = os.environ.get(
        "ENABLE_LIVE_BOUNTY_SCANNING", "false"
    ).lower() in ("true", "1", "yes")

    ctx = data.get("bounty_context")

    # If the feature flag is disabled:
    if not is_live_bounty_enabled:
        if ctx:
            return False, (
                jsonify({
                    "error": "Live bug bounty scanning is disabled on this deployment.",
                    "code": "BOUNTY_SCANNING_DISABLED",
                }),
                403,
            )
        # Regular scans proceed untouched — no passive bounty blocking
        return True, None

    if not ctx:
        # Layer 1: Passive guard (when live bounty feature is enabled)
        raw_target = (
            data.get("url") or data.get("target") or data.get("domain") or ""
        ).strip()
        scan_domain = _extract_scan_domain(raw_target)

        passive_ok, match_info = _passive_bounty_guard(scan_domain)
        if not passive_ok and match_info is not None:
            logger.warning(
                "passive_bounty_guard: blocked scan of '%s' — matched '%s' (%s, confidence=%s) on %s [%s]",
                scan_domain, match_info["asset"], match_info["status"],
                match_info["confidence"], match_info["platform"], match_info["match_type"],
            )
            log_event(
                "bounty_scan_blocked_passive",
                username, user_id,
                category="bounty", resource=scan_domain, status="blocked",
                details=json.dumps({
                    "reason":       "passive_guard_matched_known_restricted_asset",
                    "matched_asset": match_info["asset"],
                    "match_type":   match_info["match_type"],
                    "policy":       match_info["status"],
                    "confidence":   match_info["confidence"],
                    "platform":     match_info["platform"],
                    "program":      match_info["program_handle"],
                }),
            )
            return False, (
                jsonify({
                    "error": (
                        f"Scan target '{scan_domain}' matches a known Bug Bounty asset "
                        f"({match_info['asset']} on {match_info['platform']}) with a "
                        f"{match_info['status']} scan policy (confidence: {match_info['confidence']}%). "
                        "If this target belongs to a bounty program you are authorized to test, "
                        "re-submit via the Bounty Targets page with explicit policy acknowledgement."
                    ),
                    "code":          "PASSIVE_BOUNTY_BLOCK",
                    "matched_asset": match_info["asset"],
                    "match_type":    match_info["match_type"],
                    "platform":      match_info["platform"],
                    "program":       match_info["program_handle"],
                    "policy":        match_info["status"],
                    "confidence":    match_info["confidence"],
                    "signals":       match_info["signals"],
                }),
                403,
            )
        return True, None

    # Layer 2: Active gate
    asset = (ctx.get("asset") or "").strip()
    if not asset:
        return False, (
            jsonify({"error": "bounty_context.asset is required when bounty_context is present."}),
            400,
        )

    policy = ctx.get("scan_policy")
    if not policy:
        instruction = ctx.get("instruction")
        policy = _analyse_policy(instruction)

    status       = policy.get("status", "UNKNOWN")
    acknowledged = bool(ctx.get("acknowledged", False))
    platform     = ctx.get("platform", "")
    program      = ctx.get("program_handle", "")

    if status in ("RESTRICTED", "UNKNOWN") and not acknowledged:
        log_event(
            "bounty_scan_blocked_unacknowledged",
            username, user_id,
            category="bounty", resource=asset, status="blocked",
            details=json.dumps({
                "policy":   status,
                "platform": platform,
                "program":  program,
                "signals":  policy.get("signals", []),
            }),
        )
        return False, (
            jsonify({
                "error": (
                    f"Scan of '{asset}' is blocked: policy status is {status} and has "
                    "not been explicitly acknowledged. You must confirm that you have "
                    "reviewed the program policy and are authorized to test this target."
                ),
                "code":     "POLICY_GATE_BLOCKED",
                "status":   status,
                "signals":  policy.get("signals", []),
                "platform": platform,
                "program":  program,
            }),
            403,
        )

    log_event(
        "bounty_scan_acknowledged",
        username, user_id,
        category="bounty", resource=asset, status="allowed",
        details=json.dumps({
            "policy":       status,
            "confidence":   policy.get("confidence", 0),
            "acknowledged": acknowledged,
            "platform":     platform,
            "program":      program,
            "signals":      policy.get("signals", []),
        }),
    )

    bounty_meta = {
        "bounty_platform":        platform,
        "bounty_program_handle":  program,
        "bounty_asset":           asset,
        "policy_snapshot":        policy,
        "bounty_policy_snapshot": policy,
        "acknowledged":           acknowledged,
        "acknowledged_by":        username,
        "acknowledged_at":        datetime.now(timezone.utc).isoformat(),
        "bounty_acknowledged_by": username,
        "bounty_acknowledged_at": datetime.now(timezone.utc).isoformat(),
    }
    return True, bounty_meta


# ════════════════════════════════════════════════════════════════════════════
#  HTTP ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@bounty_bp.route("/api/bounty/verify-policy", methods=["POST"])
@login_required
@limiter.limit("30/minute")
@csrf.exempt
def verify_bounty_policy():
    """Pre-validate a bounty target's policy without launching a scan."""
    data = request.get_json(silent=True) or {}
    ctx  = data.get("bounty_context") or {}

    asset       = (ctx.get("asset") or "").strip()
    instruction = ctx.get("instruction") or ""

    if not asset:
        return jsonify({"error": "bounty_context.asset is required."}), 400

    policy_snapshot = ctx.get("scan_policy")
    if not policy_snapshot:
        policy_snapshot = _analyse_policy(instruction or None)

    status    = policy_snapshot.get("status", "UNKNOWN")
    blocked   = status in ("RESTRICTED", "UNKNOWN")

    return jsonify({
        "status":     status,
        "confidence": policy_snapshot.get("confidence", 0),
        "signals":    policy_snapshot.get("signals", []),
        "blocked":    blocked,
        "asset":      asset,
    })


@bounty_bp.route("/api/admin/bounty-targets")
@admin_required
def api_bounty_targets():
    """Return paginated, filtered list of bug-bounty targets."""
    platform   = request.args.get("platform", "all").lower()
    asset_type = request.args.get("asset_type", "all").upper()
    bounty     = request.args.get("bounty", "0") == "1"
    policy_filter = request.args.get("policy", "ALLOWED").upper()
    if "auto_only" in request.args and "policy" not in request.args:
        policy_filter = "ALLOWED" if request.args.get("auto_only", "1") != "0" else "ALL"
    search     = request.args.get("search", "").lower().strip()
    page       = max(1, request.args.get("page", 1, type=int))
    per_page   = min(100, max(1, request.args.get("per_page", 30, type=int)))

    platforms = list(_NORMALISERS) if platform == "all" else [platform]
    all_targets: list = []

    for plat in platforms:
        if plat not in _NORMALISERS:
            continue
        fetch_fn, norm_fn = _NORMALISERS[plat]
        raw = fetch_fn(plat)
        all_targets.extend(norm_fn(raw))

    if policy_filter != "ALL":
        all_targets = [t for t in all_targets
                       if t["scan_policy"]["status"] == policy_filter]
    if bounty:
        all_targets = [t for t in all_targets if t["eligible_bounty"]]
    if asset_type != "ALL":
        all_targets = [t for t in all_targets if t["asset_type"] == asset_type]
    if search:
        all_targets = [
            t for t in all_targets
            if search in t["asset"].lower() or search in t["program_name"].lower()
        ]

    total   = len(all_targets)
    start   = (page - 1) * per_page
    targets = all_targets[start: start + per_page]

    cache_info = {}
    for plat in platforms:
        cached = _BB_CACHE.get(plat)
        if cached:
            age = int(time.time() - cached["ts"])
            cache_info[plat] = {"age_seconds": age, "expires_in": max(0, _BB_CACHE_TTL - age)}
        else:
            cache_info[plat] = {"age_seconds": None, "expires_in": 0}

    return jsonify({
        "targets":    targets,
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "pages":      max(1, -(-total // per_page)),
        "cache_info": cache_info,
    })


@bounty_bp.route("/api/admin/bounty-targets/refresh", methods=["POST"])
@admin_required
def api_bounty_targets_refresh():
    """Force-invalidate the in-memory cache for all platforms."""
    with _BB_CACHE_LOCK:
        _BB_CACHE.clear()
    log_event("bounty_cache_refresh", current_user.username, current_user.id,
              category="admin", status="success")
    return jsonify({"ok": True, "message": "Cache cleared — data will be re-fetched on next request."})


@bounty_bp.route("/api/admin/bounty-targets/stats")
@admin_required
def api_bounty_targets_stats():
    """Return high-level stats (totals per platform) without pagination."""
    stats = {}
    for plat in _NORMALISERS:
        fetch_fn, norm_fn = _NORMALISERS[plat]
        raw     = fetch_fn(plat)
        targets = norm_fn(raw)
        allowed     = [t for t in targets if t["scan_policy"]["status"] == "ALLOWED"]
        restricted  = [t for t in targets if t["scan_policy"]["status"] == "RESTRICTED"]
        unknown     = [t for t in targets if t["scan_policy"]["status"] == "UNKNOWN"]
        bounty_list = [t for t in allowed  if t["eligible_bounty"]]
        stats[plat] = {
            "total":        len(targets),
            "allowed":      len(allowed),
            "restricted":   len(restricted),
            "unknown":      len(unknown),
            "auto_ok":      len(allowed),
            "with_bounty":  len(bounty_list),
        }
    return jsonify({"stats": stats})


# ════════════════════════════════════════════════════════════════════════════
#  WILDCARD RECONNAISSANCE PIPELINE (P1.2)
# ════════════════════════════════════════════════════════════════════════════

def _fetch_crtsh_subdomains(domain: str, timeout: int = 15) -> list[str]:
    """Fetch subdomains for a domain from crt.sh Certificate Transparency logs."""
    clean = re.sub(r"^\*\.", "", domain.strip().lower())
    url = f"https://crt.sh/?q=%.{clean}&output=json"
    headers = {"User-Agent": "HexaGuard-Recon/1.0", "Accept": "application/json"}
    subdomains: set[str] = set()
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            raw_body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw_body)
        for entry in data:
            name_val = entry.get("name_value", "")
            for line in name_val.splitlines():
                sub = line.strip().lower().lstrip("*.")
                if sub and (sub == clean or sub.endswith("." + clean)):
                    # Avoid wildcards in individual subdomain names
                    sub = sub.split("@")[-1].strip()
                    if not any(c in sub for c in (" ", "/", "\\", "*", ":")):
                        subdomains.add(sub)
    except Exception as exc:
        logger.warning("crt.sh fetch error for %s: %s", domain, exc)
    return sorted(subdomains)


def _probe_single_subdomain(subdomain: str, timeout: float = 3.0) -> dict:
    """Probe a single subdomain: DNS resolution + rapid HTTP HEAD check."""
    try:
        ip = socket.gethostbyname(subdomain)
        # SSRF guard: reject private, loopback, link-local, or reserved IPs
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return {
                "subdomain": subdomain,
                "alive": False,
                "error": "Resolves to private/reserved IP",
                "ip": ip,
            }
    except Exception as exc:
        return {
            "subdomain": subdomain,
            "alive": False,
            "error": f"DNS resolution failed: {exc}",
            "ip": None,
        }

    status_code = None
    server_hdr = None
    try:
        resp = requests.head(
            f"https://{subdomain}",
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "HexaGuard-Recon/1.0"},
        )
        status_code = resp.status_code
        server_hdr = resp.headers.get("Server", "").strip()
    except Exception:
        # Fallback to plain http if https connection fails
        try:
            resp = requests.head(
                f"http://{subdomain}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "HexaGuard-Recon/1.0"},
            )
            status_code = resp.status_code
            server_hdr = resp.headers.get("Server", "").strip()
        except Exception as exc:
            return {
                "subdomain": subdomain,
                "alive": False,
                "error": f"HTTP probe failed: {exc}",
                "ip": ip,
            }

    return {
        "subdomain": subdomain,
        "alive": True,
        "status_code": status_code,
        "server": server_hdr or "unknown",
        "ip": ip,
    }


@bounty_bp.route("/api/bounty/recon/subdomains", methods=["POST"])
@login_required
@limiter.limit("20/minute")
@csrf.exempt
def api_recon_subdomains():
    """Discover subdomains for wildcard targets.

    CRITICAL SECURITY GUARANTEE:
    - If probe_alive is True (active HEAD probe): the request MUST pass
      _enforce_bounty_policy_gate. If the target is RESTRICTED or UNKNOWN
      and has not been acknowledged, it is blocked with HTTP 403 (POLICY_GATE_BLOCKED).
    - If probe_alive is False: only passive CT log querying (crt.sh) is performed,
      sending ZERO packets to the target company.
    """
    data = request.get_json(silent=True) or {}
    raw_domain = (data.get("domain") or (data.get("bounty_context") or {}).get("asset") or "").strip()
    if not raw_domain:
        return jsonify({"error": "domain is required."}), 400

    clean_domain = _extract_scan_domain(raw_domain)
    if not clean_domain:
        return jsonify({"error": "Invalid domain provided."}), 400

    probe_alive = bool(data.get("probe_alive", False))

    # Security policy gate check for active probing
    if probe_alive:
        gate_ok, gate_result = _enforce_bounty_policy_gate(
            data, current_user.id, current_user.username
        )
        if not gate_ok:
            return gate_result

    # 1. Passive discovery via crt.sh
    discovered = _fetch_crtsh_subdomains(clean_domain)

    # 2. Alive probing (strictly guarded)
    results = []
    if probe_alive and discovered:
        # Cap at 50 subdomains per scan
        targets_to_probe = discovered[:50]
        fingerprints: set[str] = set()

        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="recon") as pool:
            future_to_sub = {
                pool.submit(_probe_single_subdomain, sub): sub
                for sub in targets_to_probe
            }
            for fut in as_completed(future_to_sub):
                try:
                    res = fut.result()
                    fp = f"{res.get('ip')}|{res.get('server')}"
                    if fp in fingerprints and res.get("alive"):
                        res["duplicate_fingerprint"] = True
                    else:
                        res["duplicate_fingerprint"] = False
                        if res.get("alive") and res.get("ip"):
                            fingerprints.add(fp)
                    results.append(res)
                except Exception as exc:
                    sub = future_to_sub[fut]
                    results.append({
                        "subdomain": sub,
                        "alive": False,
                        "error": str(exc),
                        "ip": None,
                        "duplicate_fingerprint": False,
                    })

        results.sort(key=lambda x: (not x.get("alive", False), x.get("subdomain", "")))
    else:
        for sub in discovered:
            results.append({
                "subdomain": sub,
                "alive": None,
                "status": "unprobed",
                "probe_alive": False,
                "note": "Passive discovery only (active probe requires policy acknowledgment)",
            })

    log_event(
        "bounty_wildcard_recon",
        current_user.username,
        current_user.id,
        category="bounty",
        resource=clean_domain,
        status="success",
        details=json.dumps({
            "domain": clean_domain,
            "probe_alive": probe_alive,
            "total_discovered": len(discovered),
            "alive_count": sum(1 for r in results if r.get("alive")),
        }),
    )

    return jsonify({
        "domain": clean_domain,
        "total_discovered": len(discovered),
        "probe_alive": probe_alive,
        "results": results,
    })
