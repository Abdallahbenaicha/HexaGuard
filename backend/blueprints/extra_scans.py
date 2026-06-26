"""SecurAx — Extra Scanners Blueprint.

Provides three new scan endpoints:
  POST /scan_docker      — Dockerfile / docker-compose.yml security analysis
  POST /scan_dns         — DNS & email security (SPF, DMARC, DKIM, MX, CAA, DNSSEC)
  POST /scan_wordpress   — WordPress site security audit
"""

import logging
import os
import tempfile

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from database import log_event, store_report
from extensions import csrf, limiter
from report_generator import attach_risk_breakdown, vulns_to_findings, executive_summary
from risk_engine import calculate_risk_v2
from scanners.docker_scanner    import run_docker_scan
from scanners.dns_scanner       import run_dns_scan
from scanners.wordpress_scanner import run_wordpress_scan
from utils import _check_target_lock, require_permission, validate_upload

logger = logging.getLogger(__name__)

extra_bp = Blueprint("extra_scans", __name__)


def _finalize(result: dict, breakdown, target: str) -> tuple[dict, str]:
    """Persist the report and attach risk breakdown."""
    attach_risk_breakdown(result, breakdown)
    token = store_report(
        result, breakdown.final_score, None,
        current_user.id, current_user.username,
    )
    return result, token


def _build_response(result: dict, breakdown, report_token: str) -> dict:
    findings = vulns_to_findings(result.get("vulnerabilities", []), result.get("target", ""))
    return {
        "findings":          findings,
        "risk":              breakdown.risk_level,
        "risk_score":        breakdown.final_score,
        "report_token":      report_token,
        "recommendations":   breakdown.recommendations,
        "counts":            result.get("counts", {}),
        "meta":              result.get("meta", {}),
        "executive_summary": executive_summary(
            {"result": result, "risk_score": breakdown.final_score, "stored_at": ""}
        ),
    }


# ── Docker / Container Scan ───────────────────────────────────────────────────

@extra_bp.route("/scan_docker", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("10/minute")
@csrf.exempt
def scan_docker():
    """Accept a Dockerfile or docker-compose.yml upload and return security findings."""
    upload = (
        request.files.get("file")
        or request.files.get("dockerfile")
        or request.files.get("config_file")
    )

    allowed_ext = {".dockerfile", ".yml", ".yaml", ".txt", ""}
    if upload:
        fname = upload.filename or "Dockerfile"
        ext   = os.path.splitext(fname)[1].lower()
        if ext not in allowed_ext and ext not in {".conf"}:
            return jsonify({"error": "Upload a Dockerfile, docker-compose.yml, or .yml/.yaml file."}), 400

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext or ".txt", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name

            with open(tmp_path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            if len(content.strip()) < 5:
                return jsonify({"error": "Uploaded file appears to be empty."}), 400

            result    = run_docker_scan(content, fname)
            breakdown = calculate_risk_v2(
                result, criticality=1.0, internet_facing=False,
                has_pii=False, has_payment=False, exploit_known=False,
            )
            result, token = _finalize(result, breakdown, fname)
            log_event("scan_completed", current_user.username, current_user.id,
                      category="scan", resource=fname, status="success",
                      details=f"type=docker risk={breakdown.final_score}")
            return jsonify(_build_response(result, breakdown, token))

        except Exception as exc:
            logger.exception("scan_docker error")
            return jsonify({"error": str(exc)}), 500
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # Also support raw text body (no file upload)
    body = request.get_json(silent=True) or {}
    content  = (body.get("content") or "").strip()
    filename = (body.get("filename") or "Dockerfile").strip()
    if not content:
        return jsonify({"error": "Provide a file upload or JSON body with 'content' field."}), 400

    try:
        result    = run_docker_scan(content, filename)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, token = _finalize(result, breakdown, filename)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=filename, status="success",
                  details=f"type=docker risk={breakdown.final_score}")
        return jsonify(_build_response(result, breakdown, token))
    except Exception as exc:
        logger.exception("scan_docker (body) error")
        return jsonify({"error": str(exc)}), 500


# ── DNS / Email Security Scan ─────────────────────────────────────────────────

@extra_bp.route("/scan_dns", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("10/minute")
@csrf.exempt
def scan_dns():
    """Scan a domain for DNS & email security misconfigurations."""
    data   = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("domain") or "").strip()

    if not target:
        return jsonify({"error": "Provide a domain name in the 'target' field."}), 400

    ok, err = _check_target_lock(target)
    if not ok:
        return err

    try:
        result    = run_dns_scan(target)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, token = _finalize(result, breakdown, target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=dns risk={breakdown.final_score}")
        return jsonify(_build_response(result, breakdown, token))
    except Exception as exc:
        logger.exception("scan_dns error")
        return jsonify({"error": str(exc)}), 500


# ── WordPress Security Scan ───────────────────────────────────────────────────

@extra_bp.route("/scan_wordpress", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def scan_wordpress():
    """Scan a WordPress site for security issues."""
    data   = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()

    if not target:
        return jsonify({"error": "Provide a WordPress site URL in the 'target' field."}), 400

    ok, err = _check_target_lock(target)
    if not ok:
        return err

    try:
        result    = run_wordpress_scan(target)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        result, token = _finalize(result, breakdown, target)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=wordpress risk={breakdown.final_score}")
        return jsonify(_build_response(result, breakdown, token))
    except Exception as exc:
        logger.exception("scan_wordpress error")
        return jsonify({"error": str(exc)}), 500
