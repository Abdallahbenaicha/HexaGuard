"""SecurAx — scan blueprint.

Covers:
  - /start-scan  (legacy Flask form-based dispatcher)
  - React scan bridge endpoints (/scan_url, /scan_network, etc.)
  - /health  and  /api/stats
"""

import logging
import os
import tempfile
import time

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from database import (
    get_system_stats, log_event, store_report,
    check_and_consume_quota, get_subscription, PLANS,
)
from extensions import csrf, limiter
from forms import ScanForm
import job_manager
from report_generator import (
    attach_risk_breakdown, build_network_recon, executive_summary, vulns_to_findings,
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
from utils import _check_target_lock, require_permission, require_scanner, validate_upload
from flask_cors import cross_origin

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


@scans_bp.before_request
def enforce_quota():
    """Block scan-creating POSTs when the user's monthly quota is exhausted."""
    from flask_login import current_user as _cu
    if request.method != "POST" or not _cu.is_authenticated:
        return None
    if not any(request.path.endswith(p) for p in _QUOTA_PATHS):
        return None
    allowed, used, max_scans = check_and_consume_quota(_cu.id)
    if not allowed:
        sub = get_subscription(_cu.id)
        return jsonify({
            "error": "Quota mensuel epuise. Passez a un plan superieur pour continuer.",
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
) -> tuple:
    """Attach risk breakdown, persist report, return (result, token)."""
    attach_risk_breakdown(result, breakdown)
    token = store_report(
        result, breakdown.final_score, None,
        current_user.id, current_user.username,
    )
    return result, token


# ════════════════════════════════════════════════════════════════════════════
#  HEALTH + STATS
# ════════════════════════════════════════════════════════════════════════════

@scans_bp.route("/api/version")
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
def scan_url_bridge():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "URL/target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_web_scan(target, cve_check=True, ssl_check=True)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
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
@limiter.limit("3/minute")
@csrf.exempt
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
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_nmap_scan(target, deep=deep)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
        findings = vulns_to_findings(result.get("vulnerabilities", []), target)
        recon    = build_network_recon(result)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=network risk={breakdown.final_score}")
        return jsonify({
            "findings":          findings,
            "recon":             recon,
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
def scan_dast_bridge():
    data   = request.get_json(silent=True) or {}
    target = (data.get("url") or data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target URL required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_dast_scan(target)
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
        result, report_token = _finalize_bridge_scan(result, breakdown, target)
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
@csrf.exempt
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
@csrf.exempt
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

def _ctx_finalize(result, breakdown, target, user_id, username):
    """Finalize a scan result inside a background thread (no Flask context)."""
    from database import store_report as _store
    attach_risk_breakdown(result, breakdown)
    token = _store(result, breakdown.final_score, None, user_id, username)
    return token


@scans_bp.route("/api/scan/async/web", methods=["POST"])
@require_scanner("web")
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def async_scan_web():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("web", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=web job={job_id}")

    def _run():
        result    = run_web_scan(target, cve_check=True, ssl_check=True)
        breakdown = calculate_risk_v2(result, criticality=1.0, internet_facing=True,
                                      has_pii=has_pii, has_payment=has_payment,
                                      exploit_known=exploit_known)
        token     = _ctx_finalize(result, breakdown, target, uid, uname)
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
@csrf.exempt
def async_scan_network():
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or "").strip()
    mode          = data.get("mode", "full")
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("network", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=network job={job_id}")
    deep = mode == "full"

    def _run():
        result    = run_nmap_scan(target, deep=deep)
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
@csrf.exempt
def async_scan_dast():
    data   = request.get_json(silent=True) or {}
    target = (data.get("url") or data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target URL required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err

    uid, uname = current_user.id, current_user.username
    job_id = job_manager.create_job("dast", target, uid, uname)
    log_event("scan_queued", uname, uid, category="scan", resource=target,
              details=f"async=dast job={job_id}")

    def _run():
        try:
            result = run_dast_scan(target)
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
        token    = _ctx_finalize(result, breakdown, target, uid, uname)
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
def list_scan_jobs():
    jobs = job_manager.get_user_jobs(current_user.id)
    return jsonify([
        {k: v for k, v in j.items() if k != "result"}
        for j in jobs
    ])
