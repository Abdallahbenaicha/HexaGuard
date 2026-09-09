"""SecuraX — scan blueprint.

Covers:
  - /start-scan  (legacy Flask form-based dispatcher)
  - React scan bridge endpoints (/scan_url, /scan_network, etc.)
  - /health  and  /api/stats
"""

import logging
import os
import re
import tempfile
import threading
import time

from flask import Blueprint, jsonify, render_template, request
from flask_cors import cross_origin
from flask_login import current_user, login_required

import job_manager
from blueprints.bounty import _bounty_engine_params, _enforce_bounty_policy_gate
from database import (
    PLANS,
    check_and_consume_quota,
    get_last_network_snapshot,
    get_subscription,
    get_system_stats,
    log_event,
    store_network_snapshot,
    store_report,
)
from extensions import csrf, limiter
from forms import ScanForm
from report_generator import (
    attach_risk_breakdown,
    build_network_recon,
    executive_summary,
    vulns_to_findings,
)
from risk_engine import calculate_risk_v2
from scanners.dast_scanner import run_dast_scan
from scanners.dep_scanner import run_dep_scan
from scanners.netscan_scanner import run_nmap_scan
from scanners.sast_scanner import run_sast_scan
from scanners.server_ext import run_server_scan
from scanners.server_int import generate_fixed_config, run_server_config_scan
from scanners.ssl_scanner import run_ssl_scan
from scanners.web_scanner import run_web_scan
from utils import (
    _check_target_lock,
    _is_private_ip,
    require_permission,
    require_scanner,
    validate_upload,
)

logger = logging.getLogger(__name__)

scans_bp = Blueprint("scans", __name__)

# Endpoints that consume a quota slot (all scan-creating POSTs)
_QUOTA_PATHS = {
    "/start-scan",
    "/scan_url", "/scan_network", "/analyze_code", "/fix_config",
    "/scan_server", "/scan_dast", "/scan_ssl", "/scan_dependencies",
    "/scan_docker", "/scan_dns", "/scan_wordpress",
    "/api/scan/async/web", "/api/scan/async/network",
    "/api/scan/async/dast", "/api/scan/async/ssl", "/api/scan/async/server",
}


_user_scan_history: dict[int, list[float]] = {}
_history_lock = threading.Lock()


def reset_aggregate_scan_history() -> None:
    """Reset aggregate scan rate limit history (primarily for tests)."""
    with _history_lock:
        _user_scan_history.clear()


def _check_aggregate_rate_limit(user_id: int) -> bool:
    limit = int(os.environ.get("AGGREGATE_SCAN_LIMIT_PER_MINUTE", "10"))
    now = time.time()
    cutoff = now - 60.0
    with _history_lock:
        timestamps = _user_scan_history.get(user_id, [])
        valid = [t for t in timestamps if t > cutoff]
        if len(valid) >= limit:
            _user_scan_history[user_id] = valid
            return False
        valid.append(now)
        _user_scan_history[user_id] = valid
        return True


@scans_bp.before_request
def enforce_scan_guards_and_quota():
    """Centrally enforce SSRF, target-lock, aggregate rate limits, and quota across all scan endpoints."""
    from flask_login import current_user as _cu
    if request.method != "POST" or not _cu.is_authenticated:
        return None
    if not any(request.path.endswith(p) for p in _QUOTA_PATHS):
        return None

    # Check aggregate rate limit across all scan endpoints
    if not _check_aggregate_rate_limit(_cu.id):
        return jsonify({
            "error": "Aggregate scan rate limit exceeded across all scanners. Please wait a moment before launching another scan.",
            "rate_limited": True,
        }), 429

    # 1. Extract target if present
    # NOTE: is_net is determined ONLY by the request path and scan_type — never by
    # a user-supplied "internal" field in the JSON body. This prevents a user from
    # escalating SSRF classification (check_ssrf → check_ssrf_network) by injecting
    # {"internal": true} into any scan request (SSRF classification bypass fix).
    target = None
    scan_type = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        target = data.get("target") or data.get("url") or data.get("host") or data.get("domain")
        scan_type = data.get("scan_type")
    elif request.form:
        target = request.form.get("target") or request.form.get("url") or request.form.get("host") or request.form.get("domain")
        scan_type = request.form.get("scan_type")

    non_network_endpoints = {"/analyze_code", "/fix_config", "/scan_dependencies"}
    non_network_types = {"server_int", "dependencies", "sast"}
    is_non_network = (
        any(request.path.endswith(p) for p in non_network_endpoints)
        or (scan_type in non_network_types)
    )

    if target and isinstance(target, str) and target.strip() and not is_non_network:
        is_net = (scan_type == "network_int") or request.path.endswith("/scan_network")
        ok, err_resp = _check_target_lock(target.strip(), network_scan=is_net)
        if not ok:
            return err_resp

    # 2. Check quota only if target guard passed
    allowed, used, max_scans = check_and_consume_quota(_cu.id)
    if not allowed:
        sub = get_subscription(_cu.id)
        return jsonify({
            "error": "Monthly scan quota reached. Upgrade your plan to continue.",
            "plan":       sub.get("label", sub.get("plan")),
            "scans_used": used,
            "max_scans":  max_scans,
            "upgrade":    True,
        }), 402
    return None


# ── Internal helper ────────────────────────────────────────────────────────────

def _finalize_bridge_scan(
    result: dict,
    breakdown,
    target: str,
    *,
    internet_facing: bool = True,
    has_pii: bool = False,
    has_payment: bool = False,
    exploit_known: bool = False,
    bounty_meta: "dict | None" = None,
) -> tuple:
    """Attach risk breakdown, persist report, return (result, token).

    If *bounty_meta* is supplied (set by the bounty policy gate), it is
    stored inside the result JSON so the report captures the exact policy
    state at scan time (immutable audit trail — P0.3).
    """
    attach_risk_breakdown(result, breakdown)
    if bounty_meta:
        result.setdefault("bounty", {}).update(bounty_meta)
    token = store_report(
        result, breakdown.final_score, None,
        current_user.id, current_user.username,
        bounty_meta=bounty_meta,
    )
    return result, token



# ════════════════════════════════════════════════════════════════════════════
#  HEALTH + STATS
# ════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/version")
@cross_origin(origins="*", supports_credentials=False)
def api_version():
    """Service metadata — version, available scanners."""
    return jsonify({
        "service":  "securax",
        "version":  "2.1.0",
        "scanners": ["web", "network", "sast", "dast", "dependencies", "apache", "ssl"],
        "features": ["risk_engine", "cisa_kev", "aria_ai", "2fa_totp", "pdf_reports"],
    })


@scans_bp.route("/health", methods=["GET", "OPTIONS"])
@cross_origin(origins="*", supports_credentials=False)
def health():
    """Lightweight liveness probe — called by login page to detect server wake-up."""
    try:
        from database import _get_db
        _get_db().execute("SELECT 1").fetchone()
        status = "ok"
    except Exception:
        status = "degraded"
    return jsonify({"status": status, "service": "securax"}), 200


@scans_bp.route("/api/stats")
@login_required
def platform_stats():
    """Public platform-level counters for the scan form stats bar."""
    try:
        raw = get_system_stats()
        return jsonify({
            "total_scans": int(raw.get("total_scans", 0)),
            "total_vulns": int(raw.get("total_vulns",  0)),
        })
    except Exception:
        return jsonify({"total_scans": 0, "total_vulns": 0})


# ════════════════════════════════════════════════════════════════════════════
#  LEGACY FORM-BASED SCAN  (used by Flask HTML frontend)
# ════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/start-scan", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
def start_scan():
    form = ScanForm()
    if not form.validate_on_submit():
        return jsonify({"error": "بيانات غير صالحة.", "details": form.errors}), 400

    target        = form.target.data.strip()
    scan_type     = form.scan_type.data
    deep_scan     = form.deep_scan.data
    cve_check     = form.cve_check.data
    ssl_check     = form.ssl_check.data
    has_pii       = bool(form.has_pii.data)
    has_payment   = bool(form.has_payment.data)
    exploit_known = bool(form.exploit_known.data)

    EXTERNAL_TYPES = {"network_ext", "web", "server_ext", "dast"}
    if scan_type in EXTERNAL_TYPES and not form.legal_disclaimer.data:
        return jsonify({"error": "يجب الموافقة على الإقرار القانوني للفحوصات الخارجية."}), 400

    NON_NETWORK_TYPES = {"server_int", "dependencies", "sast"}
    if scan_type not in NON_NETWORK_TYPES:
        ok, err_resp = _check_target_lock(target, network_scan=(scan_type == "network_int"))
        if not ok:
            return err_resp

    scan_start_time = time.perf_counter()

    try:
        criticality = float(form.criticality.data)
    except (ValueError, TypeError):
        return jsonify({"error": "قيمة criticality غير صالحة."}), 400

    logger.info("scan start | user=%s | type=%s | target=%s",
                current_user.username, scan_type, target)
    log_event("scan_started", current_user.username, current_user.id,
              category="scan", resource=target, ip_address=request.remote_addr,
              details=f"type={scan_type}")

    result   = None
    tmp_path = None
    original_config_content = None

    try:
        if scan_type == "network_ext":
            result = run_nmap_scan(target, deep=deep_scan)
        elif scan_type == "network_int":
            result = run_nmap_scan(target, deep=deep_scan, internal=True)
        elif scan_type == "web":
            result = run_web_scan(target, cve_check=cve_check, ssl_check=ssl_check)
        elif scan_type == "server_ext":
            result = run_server_scan(target, deep=deep_scan)
        elif scan_type == "server_int":
            upload = request.files.get("config_file")
            ok, err = validate_upload(upload, {".conf", ".txt"})
            if not ok:
                return jsonify({"error": err}), 400
            with tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            try:
                with open(tmp_path, encoding="utf-8", errors="replace") as _fh:
                    original_config_content = _fh.read()
            except OSError:
                pass
            result = run_server_config_scan(tmp_path)
        elif scan_type == "dependencies":
            upload = request.files.get("config_file")
            ok, err = validate_upload(upload, {".txt", ".json", ".toml"})
            if not ok:
                return jsonify({"error": err}), 400
            fname  = upload.filename.lower()
            suffix = ".json" if fname.endswith(".json") else (".toml" if fname.endswith(".toml") else ".txt")
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            named_path = os.path.join(tempfile.gettempdir(), os.path.basename(upload.filename))
            try:
                os.replace(tmp_path, named_path)
                tmp_path = named_path
            except OSError:
                pass
            result = run_dep_scan(tmp_path)
        elif scan_type == "sast":
            upload = request.files.get("source_file") or request.files.get("config_file")
            ok, err = validate_upload(upload, {".zip"})
            if not ok:
                return jsonify({"error": err}), 400
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            result = run_sast_scan(tmp_path)
        elif scan_type == "dast":
            result = run_dast_scan(target)
        else:
            return jsonify({"error": "نوع فحص غير مدعوم."}), 400

    except RuntimeError as exc:
        logger.error("scan failed | %s | %s | %s", target, scan_type, exc)
        return jsonify({"error": str(exc)}), 500
    except Exception:
        logger.exception("unexpected scan error | target=%s", target)
        return jsonify({"error": "حدث خطأ غير متوقع أثناء الفحص."}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    scan_duration_seconds = round(time.perf_counter() - scan_start_time, 2)
    if isinstance(result, dict):
        result["scan_duration_seconds"] = scan_duration_seconds

    internet_facing = scan_type in {"network_ext", "web", "server_ext", "dast"}
    breakdown = calculate_risk_v2(
        result,
        criticality=criticality,
        internet_facing=internet_facing,
        has_pii=has_pii,
        has_payment=has_payment,
        exploit_known=exploit_known,
    )
    risk_score = breakdown.final_score

    result["risk_breakdown"] = {
        "base_score":        breakdown.base_score,
        "temporal_score":    breakdown.temporal_score,
        "env_score":         breakdown.env_score,
        "final_score":       breakdown.final_score,
        "risk_level":        breakdown.risk_level,
        "confidence":        breakdown.confidence,
        "recommendations":   breakdown.recommendations,
        "attack_chains":     breakdown.attack_chains,
        "cisa_kev_findings": breakdown.cisa_kev_findings,
    }

    report_token = store_report(result, risk_score, original_config_content,
                                current_user.id, current_user.username)

    log_event("scan_completed", current_user.username, current_user.id,
              category="scan", resource=target, status="success",
              details=f"type={scan_type} risk={risk_score} level={breakdown.risk_level} "
                      f"findings={len(result.get('vulnerabilities', []))}")

    return jsonify({
        "scan_result":           result,
        "risk_score":            risk_score,
        "risk_level":            breakdown.risk_level,
        "confidence":            breakdown.confidence,
        "recommendations":       breakdown.recommendations,
        "attack_chains":         breakdown.attack_chains,
        "cisa_kev_findings":     breakdown.cisa_kev_findings,
        "scan_duration_seconds": scan_duration_seconds,
        "message":               "تم الفحص بنجاح.",
        "report_token":          report_token,
    })


# ════════════════════════════════════════════════════════════════════════════
#  REACT SCAN BRIDGES
# ════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/scan_url", methods=["POST"])
@require_scanner("web")
@require_permission("run_scan")
@limiter.limit("5/minute")
def scan_url_bridge():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "URL/target required."}), 400

    # ── P0.1: Bounty policy gate (no-op when bounty_context absent) ───────────
    gate_ok, gate_result = _enforce_bounty_policy_gate(
        data, current_user.id, current_user.username
    )
    if not gate_ok:
        return gate_result
    bounty_meta = gate_result  # dict or None

    # ── P0.2 & P1.1: Rate-limit and throttle enforcement ───────────────────────
    policy_snapshot = (data.get("bounty_context") or {}).get("scan_policy") or {}
    enforced_rate, enforced_threads = _bounty_engine_params(policy_snapshot)
    if "rate_limit" in data and isinstance(data["rate_limit"], (int, float)):
        effective_rate = min(enforced_rate, max(1, int(data["rate_limit"])))
    else:
        effective_rate = enforced_rate

    # ── P0.4: Auth/session support & P1.3: Researcher attribution header ───────
    auth_cfg      = data.get("auth_config") or {}
    extra_headers: dict = {}
    if auth_cfg.get("cookie"):
        extra_headers["Cookie"] = str(auth_cfg["cookie"])
    if auth_cfg.get("bearer_token"):
        extra_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
    if isinstance(auth_cfg.get("custom_headers"), dict):
        extra_headers.update({
            str(k): str(v)
            for k, v in auth_cfg["custom_headers"].items()
            if k and v
        })
    # P1.3: Attribution header scoped strictly to bounty_context scans
    bounty_ctx = data.get("bounty_context")
    if bounty_ctx:
        attr_val = bounty_ctx.get("attribution_header") or f"SecuraX-Bounty-Scanner/1.0 (+user: {current_user.username})"
        extra_headers["X-Bug-Bounty-Hacker"] = current_user.username
        extra_headers["User-Agent"] = attr_val

    # RBAC safety: do NOT auto-route private IPs to nmap from this endpoint.
    # scan_url_bridge is guarded by @require_scanner("web") only — silently
    # running nmap here would bypass the separate "network" scanner permission.
    # Users who wish to scan internal network targets must use /scan_network
    # (which requires @require_scanner("network") explicitly).
    bare = re.sub(r"^https?://", "", target.strip()).split("/")[0].split("?")[0].split(":")[0].lower()
    if _is_private_ip(bare):
        return jsonify({
            "error": (
                "Web scanner cannot target private/internal IP addresses. "
                "To scan internal network targets, use the Network Scanner (/scan_network) "
                "which requires the appropriate network scanner permission."
            ),
            "ssrf_blocked": True,
        }), 403

    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_web_scan(
            target, cve_check=True, ssl_check=True,
            extra_headers=extra_headers or None,
            rate_limit=enforced_rate,
        )
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        result, report_token = _finalize_bridge_scan(
            result, breakdown, target, bounty_meta=bounty_meta
        )
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=web risk={breakdown.final_score}")
        return jsonify({
            "findings":          findings,
            "risk":              breakdown.risk_level,
            "risk_score":        breakdown.final_score,
            "report_token":      report_token,
            "recommendations":   breakdown.recommendations,
            "attack_chains":     breakdown.attack_chains,
            "executive_summary": executive_summary(
                {"result": result, "risk_score": breakdown.final_score, "stored_at": ""}
            ),
        })
    except Exception as exc:
        logger.exception("scan_url_bridge error")
        return jsonify({"error": str(exc)}), 500



@scans_bp.route("/scan_network", methods=["POST"])
@require_scanner("network")
@require_permission("run_scan")
@limiter.limit(lambda: "1000/minute" if os.environ.get("RATELIMIT_ENABLED", "true").lower() == "false" else "3/minute")
def scan_network_bridge():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or "").strip()
    mode          = data.get("mode", "full")
    deep          = mode == "full"
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    # Network scanner: allow private/internal IPs (internal infra scanning is
    # a core use-case). _check_target_lock with network_scan=True uses the
    # lighter SSRF check that permits RFC-1918 ranges.
    ok, err = _check_target_lock(target, network_scan=True)
    if not ok:
        return err
    # Auto-detect internal mode so nmap uses appropriate timing/flags
    bare = target.split("/")[0].split("?")[0].split(":")[0].lower().strip()
    internal = _is_private_ip(bare)

    # Retrieve last snapshot BEFORE this scan so we can diff afterward
    prev_snapshot = get_last_network_snapshot(target, current_user.id)

    try:
        result = run_nmap_scan(target, deep=deep, internal=internal)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        recon    = build_network_recon(result)

        # Build lightweight hosts summary for snapshot storage + history diff
        hosts_summary = [
            {
                "host":     h.get("host", ""),
                "hostname": h.get("hostname", ""),
                "ports": [
                    {
                        "port":     p["port"],
                        "service":  p.get("service", ""),
                        "protocol": p.get("protocol", "tcp"),
                    }
                    for p in recon.get("open_port_list", [])
                    if p.get("host") == h.get("host")
                ],
            }
            for h in result.get("hosts", [])
        ]

        # Persist snapshot (non-fatal)
        try:
            store_network_snapshot(target, current_user.id, hosts_summary)
        except Exception:
            pass

        # Compute diff against previous snapshot
        history = None
        if prev_snapshot:
            curr_map = {h["host"]: h for h in hosts_summary}
            prev_map = {h["host"]: h for h in prev_snapshot}
            new_devices     = [{"host": ip, "hostname": curr_map[ip].get("hostname", "")}
                               for ip in curr_map if ip not in prev_map]
            removed_devices = [{"host": ip, "hostname": prev_map[ip].get("hostname", "")}
                               for ip in prev_map if ip not in curr_map]
            port_changes = []
            for ip in curr_map:
                if ip not in prev_map:
                    continue
                curr_ps = {f"{p['port']}/{p.get('protocol','tcp')}" for p in curr_map[ip].get("ports", [])}
                prev_ps = {f"{p['port']}/{p.get('protocol','tcp')}" for p in prev_map[ip].get("ports", [])}
                new_p   = [p for p in curr_map[ip].get("ports", [])
                           if f"{p['port']}/{p.get('protocol','tcp')}" not in prev_ps]
                closed_p = [p for p in prev_map[ip].get("ports", [])
                            if f"{p['port']}/{p.get('protocol','tcp')}" not in curr_ps]
                if new_p or closed_p:
                    port_changes.append({"host": ip, "new_ports": new_p, "closed_ports": closed_p})
            history = {
                "new_devices":     new_devices,
                "removed_devices": removed_devices,
                "port_changes":    port_changes,
                "has_changes":     bool(new_devices or removed_devices or port_changes),
            }

        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=network risk={breakdown.final_score}")
        return jsonify({
            "findings":          findings,
            "recon":             recon,
            "history":           history,
            "risk":              breakdown.risk_level,
            "risk_score":        breakdown.final_score,
            "report_token":      report_token,
            "recommendations":   breakdown.recommendations,
            "attack_chains":     breakdown.attack_chains,
            "executive_summary": executive_summary(
                {"result": result, "risk_score": breakdown.final_score, "stored_at": ""}
            ),
        })
    except Exception as exc:
        logger.exception("scan_network_bridge error")
        return jsonify({"error": str(exc)}), 500


@scans_bp.route("/analyze_code", methods=["POST"])
@require_scanner("code")
@require_permission("run_scan")
@limiter.limit("5/minute")
def analyze_code_bridge():
    upload = request.files.get("file") or request.files.get("source_file")
    ok_val, err = validate_upload(upload, {".zip"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        result = run_sast_scan(tmp_path)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, report_token = _finalize_bridge_scan(
            result, breakdown, upload.filename or "source.zip"
        )
        findings = vulns_to_findings(result.get("vulnerabilities", []), upload.filename or "")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("analyze_code_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@scans_bp.route("/fix_config", methods=["POST"])
@require_scanner("config")
@require_permission("run_scan")
@limiter.limit("5/minute")
def fix_config_bridge():
    upload = request.files.get("file") or request.files.get("config_file")
    ok_val, err = validate_upload(upload, {".conf", ".txt"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        with open(tmp_path, encoding="utf-8-sig", errors="replace") as _fh:
            original = _fh.read()
        result    = run_server_config_scan(tmp_path)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        attach_risk_breakdown(result, breakdown)
        report_token = store_report(
            result, breakdown.final_score, original,
            current_user.id, current_user.username,
        )
        findings = vulns_to_findings(result.get("vulnerabilities", []), upload.filename or "")
        fixed_content, change_log = generate_fixed_config(original, result.get("vulnerabilities", []))
        return jsonify({
            "findings":      findings,
            "fixed_config":  fixed_content,
            "changes":       change_log,
            "change_log":    change_log,
            "changes_count": len(change_log),
            "filename":      "httpd_securax_fixed.conf",
            "risk":          breakdown.risk_level,
            "risk_score":    breakdown.final_score,
            "report_token":  report_token,
        })
    except Exception as exc:
        logger.exception("fix_config_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@scans_bp.route("/scan_server", methods=["POST"])
@require_scanner("server")
@require_permission("run_scan")
@limiter.limit("3/minute")
def scan_server_bridge():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or data.get("url") or "").strip()
    deep          = bool(data.get("deep", False))
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_server_scan(target, deep=deep)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=server_ext risk={breakdown.final_score}")
        return jsonify({
            "findings":       findings,
            "risk":           breakdown.risk_level,
            "risk_score":     breakdown.final_score,
            "server_type":    result.get("server_type", "unknown"),
            "server_version": result.get("server_version", ""),
            "report_token":   report_token,
        })
    except Exception as exc:
        logger.exception("scan_server_bridge error")
        return jsonify({"error": str(exc)}), 500


@scans_bp.route("/scan_dast", methods=["POST"])
@require_scanner("dast")
@require_permission("run_scan")
@limiter.limit("5/minute")
def scan_dast_bridge():
    data   = request.get_json(silent=True) or {}
    target = (data.get("url") or data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target URL required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    # ── P0.1: Bounty policy gate ───────────────────────────────────────────────
    gate_ok, gate_result = _enforce_bounty_policy_gate(
        data, current_user.id, current_user.username
    )
    if not gate_ok:
        return gate_result
    bounty_meta = gate_result  # dict or None

    # ── P0.2 & P1.1: Rate-limit and engine controls ───────────────────────────
    policy_snapshot = (data.get("bounty_context") or {}).get("scan_policy") or {}
    enforced_rate, enforced_threads = _bounty_engine_params(policy_snapshot)
    if "rate_limit" in data and isinstance(data["rate_limit"], (int, float)):
        effective_rate = min(enforced_rate, max(1, int(data["rate_limit"])))
    else:
        effective_rate = enforced_rate

    if "threads" in data and isinstance(data["threads"], (int, float)):
        effective_threads = min(enforced_threads, max(1, int(data["threads"])))
    else:
        effective_threads = enforced_threads

    enabled_engines = data.get("enabled_engines")

    # ── P0.4: Auth/session support & P1.3: Researcher attribution header ───────
    auth_cfg      = data.get("auth_config") or {}
    extra_headers: dict = {}
    if auth_cfg.get("cookie"):
        extra_headers["Cookie"] = str(auth_cfg["cookie"])
    if auth_cfg.get("bearer_token"):
        extra_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
    if isinstance(auth_cfg.get("custom_headers"), dict):
        extra_headers.update({
            str(k): str(v)
            for k, v in auth_cfg["custom_headers"].items()
            if k and v
        })
    # P1.3: Attribution header scoped strictly to bounty_context scans
    bounty_ctx = data.get("bounty_context")
    if bounty_ctx:
        attr_val = bounty_ctx.get("attribution_header") or f"SecuraX-Bounty-Scanner/1.0 (+user: {current_user.username})"
        extra_headers["X-Bug-Bounty-Hacker"] = current_user.username
        extra_headers["User-Agent"] = attr_val

    from scanners.dast_scanner import DASTConfig
    dast_cfg = DASTConfig(
        rate_limit=effective_rate,
        threads=effective_threads,
        enabled_engines=enabled_engines,
        extra_headers=extra_headers or None,
    )
    try:
        result = run_dast_scan(target, config=dast_cfg)
    except ValueError as exc:
        return jsonify({"error": f"Target blocked by security policy: {exc}"}), 400
    except (RuntimeError, OSError) as exc:
        result = {
            "scan_type": "dast", "target": target,
            "vulnerabilities": [{
                "title": "DAST Scan Unavailable",
                "severity": "INFO",
                "description": f"DAST scan could not start: {exc}",
                "evidence": "", "remediation": "Check that the target URL is reachable.",
            }],
            "meta": {
                "scan_time": "", "profile": "standard",
                "tools": [], "target_url": target, "issues_found": 0,
            },
        }
    except Exception as exc:
        logger.exception("scan_dast_bridge error")
        return jsonify({"error": str(exc)}), 500
    try:
        vulns  = result.get("vulnerabilities", [])
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, report_token = _finalize_bridge_scan(
            result, breakdown, target, bounty_meta=bounty_meta
        )
        findings = vulns_to_findings(vulns, target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=dast risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_dast_bridge post-scan error")
        return jsonify({"error": str(exc)}), 500


@scans_bp.route("/scan_ssl", methods=["POST"])
@require_scanner("ssl")
@require_permission("run_scan")
@limiter.limit("5/minute")
def scan_ssl_bridge():
    data   = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "Target hostname or URL required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result    = run_ssl_scan(target)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=bool(data.get("has_pii", False)),
            has_payment=bool(data.get("has_payment", False)),
            exploit_known=False,
        )
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=ssl risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
            "meta":         result.get("meta", {}),
        })
    except Exception as exc:
        logger.exception("scan_ssl_bridge error")
        return jsonify({"error": str(exc)}), 500


@scans_bp.route("/scan_dependencies", methods=["POST"])
@require_scanner("deps")
@require_permission("run_scan")
@limiter.limit("5/minute")
def scan_dependencies_bridge():
    upload = request.files.get("file") or request.files.get("package_file")
    ok_val, err = validate_upload(upload, {".json", ".txt", ".toml"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        fname  = upload.filename.lower()
        suffix = ".json" if fname.endswith(".json") else (".toml" if fname.endswith(".toml") else ".txt")
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        result = run_dep_scan(tmp_path)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, report_token = _finalize_bridge_scan(
            result, breakdown, upload.filename or "dependencies",
        )
        findings = vulns_to_findings(result.get("vulnerabilities", []), upload.filename or "")
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource="dependencies", status="success",
                  details=f"type=dep risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_dependencies_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ════════════════════════════════════════════════════════════════════════════
#  ASYNC SCAN ENDPOINTS  — start in background, poll /api/scan/job/<id>
# ════════════════════════════════════════════════════════════════════════════

def _ctx_finalize(result, breakdown, target, user_id, username, bounty_meta=None):
    """Finalize a scan result inside a background thread (no Flask context)."""
    from database import store_report as _store
    attach_risk_breakdown(result, breakdown)
    if bounty_meta:
        result.setdefault("bounty", {}).update(bounty_meta)
    token = _store(result, breakdown.final_score, None, user_id, username, bounty_meta=bounty_meta)
    return token


@scans_bp.route("/api/scan/async/web", methods=["POST"])
@require_scanner("web")
@require_permission("run_scan")
@limiter.limit("5/minute")
def async_scan_web():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400

    # ── P0.1: Bounty policy gate ───────────────────────────────────────────────
    gate_ok, gate_result = _enforce_bounty_policy_gate(
        data, current_user.id, current_user.username
    )
    if not gate_ok:
        return gate_result
    bounty_meta = gate_result

    # ── P0.2 & P1.1: Rate-limit and throttle enforcement ───────────────────────
    policy_snapshot = (data.get("bounty_context") or {}).get("scan_policy") or {}
    enforced_rate, enforced_threads = _bounty_engine_params(policy_snapshot)
    if "rate_limit" in data and isinstance(data["rate_limit"], (int, float)):
        effective_rate = min(enforced_rate, max(1, int(data["rate_limit"])))
    else:
        effective_rate = enforced_rate

    # ── P0.4: Auth/session support & P1.3: Researcher attribution header ───────
    auth_cfg      = data.get("auth_config") or {}
    extra_headers: dict = {}
    if auth_cfg.get("cookie"):
        extra_headers["Cookie"] = str(auth_cfg["cookie"])
    if auth_cfg.get("bearer_token"):
        extra_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
    if isinstance(auth_cfg.get("custom_headers"), dict):
        extra_headers.update({
            str(k): str(v)
            for k, v in auth_cfg["custom_headers"].items()
            if k and v
        })
    # P1.3: Attribution header scoped strictly to bounty_context scans
    bounty_ctx = data.get("bounty_context")
    if bounty_ctx:
        attr_val = bounty_ctx.get("attribution_header") or f"SecuraX-Bounty-Scanner/1.0 (+user: {current_user.username})"
        extra_headers["X-Bug-Bounty-Hacker"] = current_user.username
        extra_headers["User-Agent"] = attr_val

    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("web", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=web job={job_id}")

    def _run():
        result    = run_web_scan(
            target, cve_check=True, ssl_check=True,
            extra_headers=extra_headers or None,
            rate_limit=enforced_rate,
        )
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=has_pii, has_payment=has_payment,
                                      exploit_known=exploit_known)
        token     = _ctx_finalize(result, breakdown, target, uid, uname, bounty_meta=bounty_meta)
        findings  = vulns_to_findings(result.get("vulnerabilities", []), target)
        return {
            "findings": findings, "risk": breakdown.risk_level,
            "risk_score": breakdown.final_score, "report_token": token,
            "recommendations": breakdown.recommendations,
            "executive_summary": executive_summary(
                {"result": result, "risk_score": breakdown.final_score, "stored_at": ""}
            ),
        }

    job_manager.run_in_background(job_id, _run)
    return jsonify({"job_id": job_id, "status": "queued"})


@scans_bp.route("/api/scan/async/network", methods=["POST"])
@require_scanner("network")
@require_permission("run_scan")
@limiter.limit("3/minute")
def async_scan_network():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or "").strip()
    mode          = data.get("mode", "full")
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target, network_scan=True)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("network", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=network job={job_id}")
    deep = mode == "full"
    bare_async = target.split("/")[0].split("?")[0].split(":")[0].lower().strip()
    internal_async = _is_private_ip(bare_async)

    def _run():
        result    = run_nmap_scan(target, deep=deep, internal=internal_async)
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=has_pii, has_payment=has_payment,
                                      exploit_known=exploit_known)
        token     = _ctx_finalize(result, breakdown, target, uid, uname)
        findings  = vulns_to_findings(result.get("vulnerabilities", []), target)
        recon     = build_network_recon(result)
        return {
            "findings": findings, "recon": recon, "risk": breakdown.risk_level,
            "risk_score": breakdown.final_score, "report_token": token,
            "recommendations": breakdown.recommendations,
        }

    job_manager.run_in_background(job_id, _run)
    return jsonify({"job_id": job_id, "status": "queued"})


@scans_bp.route("/api/scan/async/dast", methods=["POST"])
@require_scanner("dast")
@require_permission("run_scan")
@limiter.limit("5/minute")
def async_scan_dast():
    data   = request.get_json(silent=True) or {}
    target = (data.get("url") or data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target URL required."}), 400

    # ── P0.1: Bounty policy gate ───────────────────────────────────────────────
    gate_ok, gate_result = _enforce_bounty_policy_gate(
        data, current_user.id, current_user.username
    )
    if not gate_ok:
        return gate_result
    bounty_meta = gate_result

    # ── P0.2 & P1.1: Rate-limit and engine controls ───────────────────────────
    policy_snapshot = (data.get("bounty_context") or {}).get("scan_policy") or {}
    enforced_rate, enforced_threads = _bounty_engine_params(policy_snapshot)
    if "rate_limit" in data and isinstance(data["rate_limit"], (int, float)):
        effective_rate = min(enforced_rate, max(1, int(data["rate_limit"])))
    else:
        effective_rate = enforced_rate

    if "threads" in data and isinstance(data["threads"], (int, float)):
        effective_threads = min(enforced_threads, max(1, int(data["threads"])))
    else:
        effective_threads = enforced_threads

    enabled_engines = data.get("enabled_engines")

    # ── P0.4: Auth/session support & P1.3: Researcher attribution header ───────
    auth_cfg      = data.get("auth_config") or {}
    extra_headers: dict = {}
    if auth_cfg.get("cookie"):
        extra_headers["Cookie"] = str(auth_cfg["cookie"])
    if auth_cfg.get("bearer_token"):
        extra_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
    if isinstance(auth_cfg.get("custom_headers"), dict):
        extra_headers.update({
            str(k): str(v)
            for k, v in auth_cfg["custom_headers"].items()
            if k and v
        })
    # P1.3: Attribution header scoped strictly to bounty_context scans
    bounty_ctx = data.get("bounty_context")
    if bounty_ctx:
        attr_val = bounty_ctx.get("attribution_header") or f"SecuraX-Bounty-Scanner/1.0 (+user: {current_user.username})"
        extra_headers["X-Bug-Bounty-Hacker"] = current_user.username
        extra_headers["User-Agent"] = attr_val

    from scanners.dast_scanner import DASTConfig
    dast_cfg = DASTConfig(
        rate_limit=effective_rate,
        threads=effective_threads,
        enabled_engines=enabled_engines,
        extra_headers=extra_headers or None,
    )

    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("dast", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=dast job={job_id}")

    def _run():
        try:
            result = run_dast_scan(target, config=dast_cfg)
        except (ValueError, RuntimeError, OSError) as exc:
            result = {
                "scan_type": "dast", "target": target,
                "vulnerabilities": [{"title": "DAST Unavailable", "severity": "INFO",
                                      "description": str(exc), "evidence": "",
                                      "remediation": "Check target reachability."}],
                "meta": {"scan_time": "", "profile": "standard",
                         "tools": [], "target_url": target, "issues_found": 0},
            }
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=False, has_payment=False, exploit_known=False)
        token    = _ctx_finalize(result, breakdown, target, uid, uname, bounty_meta=bounty_meta)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        return {
            "findings": findings, "risk": breakdown.risk_level,
            "risk_score": breakdown.final_score, "report_token": token,
        }

    job_manager.run_in_background(job_id, _run)
    return jsonify({"job_id": job_id, "status": "queued"})


@scans_bp.route("/api/scan/async/ssl", methods=["POST"])
@require_scanner("ssl")
@require_permission("run_scan")
@limiter.limit("5/minute")
def async_scan_ssl():
    data        = request.get_json(silent=True) or {}
    target      = (data.get("target") or data.get("url") or "").strip()
    has_pii     = bool(data.get("has_pii", False))
    has_payment = bool(data.get("has_payment", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("ssl", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=ssl job={job_id}")

    def _run():
        result    = run_ssl_scan(target)
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=has_pii, has_payment=has_payment,
                                      exploit_known=False)
        token    = _ctx_finalize(result, breakdown, target, uid, uname)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        return {
            "findings": findings, "risk": breakdown.risk_level,
            "risk_score": breakdown.final_score, "report_token": token,
            "meta": result.get("meta", {}),
        }

    job_manager.run_in_background(job_id, _run)
    return jsonify({"job_id": job_id, "status": "queued"})


@scans_bp.route("/api/scan/async/server", methods=["POST"])
@require_scanner("server")
@require_permission("run_scan")
@limiter.limit("3/minute")
def async_scan_server():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or data.get("url") or "").strip()
    deep          = bool(data.get("deep", False))
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("server_ext", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=server_ext job={job_id}")

    def _run():
        result    = run_server_scan(target, deep=deep)
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=has_pii, has_payment=has_payment,
                                      exploit_known=exploit_known)
        token    = _ctx_finalize(result, breakdown, target, uid, uname)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        return {
            "findings": findings, "risk": breakdown.risk_level,
            "risk_score": breakdown.final_score, "report_token": token,
            "server_type": result.get("server_type", "unknown"),
            "server_version": result.get("server_version", ""),
        }

    job_manager.run_in_background(job_id, _run)
    return jsonify({"job_id": job_id, "status": "queued"})


# ── Job status polling ────────────────────────────────────────────────────────

@scans_bp.route("/api/scan/job/<job_id>")
@require_permission("run_scan")
def get_scan_job(job_id):
    job = job_manager.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found or expired."}), 404
    if job["user_id"] != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Not authorized."}), 403
    payload = {k: v for k, v in job.items() if k != "result"}
    if job["status"] == "done":
        payload["result"] = job["result"]
    return jsonify(payload)


@scans_bp.route("/api/scan/jobs")
@require_permission("run_scan")
def list_scan_jobs():
    jobs = job_manager.get_user_jobs(current_user.id)
    return jsonify([
        {k: v for k, v in j.items() if k != "result"}
        for j in jobs
    ])


@scans_bp.route("/api/scan/job/<job_id>/dismiss", methods=["DELETE"])
@require_permission("run_scan")
def dismiss_scan_job(job_id):
    ok = job_manager.dismiss_job(job_id, current_user.id)
    if not ok:
        return jsonify({"error": "Cannot dismiss a running or queued job."}), 400
    return jsonify({"ok": True})


@scans_bp.route("/api/scan/jobs/errors", methods=["DELETE"])
@require_permission("run_scan")
def dismiss_all_error_jobs():
    count = job_manager.dismiss_all_errors(current_user.id)
    return jsonify({"ok": True, "removed": count})


@scans_bp.route("/api/scanners/status", methods=["GET"])
def api_scanners_status():
    """Return availability and readiness status of security scanning tools."""
    import shutil
    import os

    tools = {
        "nuclei": {
            "name": "Nuclei",
            "available": bool(shutil.which("nuclei") or os.environ.get("PDCP_API_KEY")),
            "provider": "cloud_api" if os.environ.get("PDCP_API_KEY") else ("cli" if shutil.which("nuclei") else "missing"),
            "path": shutil.which("nuclei") or ("Cloud API (PDCP)" if os.environ.get("PDCP_API_KEY") else None),
            "category": "dast",
            "install_hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "nikto": {
            "name": "Nikto",
            "available": bool(shutil.which("nikto")),
            "provider": "cli" if shutil.which("nikto") else "missing",
            "path": shutil.which("nikto"),
            "category": "dast",
            "install_hint": "apt install nikto / brew install nikto",
        },
        "zap": {
            "name": "OWASP ZAP",
            "available": bool(shutil.which("zap.sh") or shutil.which("zap") or os.environ.get("ZAP_URL")),
            "provider": "daemon" if os.environ.get("ZAP_URL") else ("cli" if shutil.which("zap.sh") or shutil.which("zap") else "missing"),
            "path": os.environ.get("ZAP_URL") or shutil.which("zap.sh") or shutil.which("zap"),
            "category": "dast",
            "install_hint": "docker run -d -p 8080:8080 zaproxy/zap-stable",
        },
        "nmap": {
            "name": "Nmap",
            "available": bool(shutil.which("nmap")),
            "provider": "cli" if shutil.which("nmap") else "missing",
            "path": shutil.which("nmap"),
            "category": "network",
            "install_hint": "apt install nmap / nmap.org",
        },
        "trivy": {
            "name": "Trivy",
            "available": bool(shutil.which("trivy")),
            "provider": "cli" if shutil.which("trivy") else "missing",
            "path": shutil.which("trivy"),
            "category": "docker",
            "install_hint": "apt install trivy",
        },
        "sslyze": {
            "name": "SSLyze",
            "available": bool(shutil.which("sslyze")),
            "provider": "cli" if shutil.which("sslyze") else "python_fallback",
            "path": shutil.which("sslyze"),
            "category": "ssl",
            "install_hint": "pip install sslyze",
        },
    }

    dast_missing = [t["name"] for t in tools.values() if t["category"] == "dast" and not t["available"]]
    return jsonify({
        "ok": True,
        "tools": tools,
        "dast_ready": len(dast_missing) == 0,
        "dast_partial": any(t["available"] for t in tools.values() if t["category"] == "dast"),
        "dast_missing": dast_missing,
    })
