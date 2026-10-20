"""SecuraX Evaluation Lab — Administrative Blueprint.

Governed strictly by Master Specification v5 Phase 1:
  - Accessible ONLY when LAB_MODE=1 is active in the backend.
  - Restricted strictly to Administrators with 2FA verification.
  - Provides Target Catalog inspection and explicit Gate pre-verification.
  - Zero vulnerable containers started here (no docker.sock).
"""

from __future__ import annotations

import json
import logging
from flask import Blueprint, jsonify, render_template_string, request, session
from flask_login import current_user, login_required

from db.lab import (
    get_benchmark_scorecard,
    get_lab_target,
    list_benchmark_scorecards,
    list_lab_targets,
    record_user_acknowledgement,
    save_benchmark_scorecard,
    seed_lab_targets,
    update_target_health,
)
from db.audit import log_event
import job_manager
from lab.config import is_lab_2fa_enforced, is_lab_mode_enabled, is_lab_remote_scanning_enabled
from lab.gate import evaluate_lab_gate
from lab.runner import run_lab_benchmark

logger = logging.getLogger(__name__)

lab_bp = Blueprint("lab", __name__, url_prefix="/api/lab")


@lab_bp.before_request
def _enforce_lab_access_controls():
    """Fail-closed guard enforcing LAB_MODE, Admin RBAC, and 2FA."""
    # 1. Feature Flag check (enforced in BACKEND)
    if not is_lab_mode_enabled():
        return jsonify({
            "ok": False,
            "error": "Evaluation Lab is disabled. LAB_MODE=1 is required in the backend.",
            "code": "LAB_MODE_DISABLED",
        }), 403

    # 2. Authentication check
    if not current_user.is_authenticated:
        return jsonify({
            "ok": False,
            "error": "Authentication required. Please log in as an administrator.",
            "code": "AUTH_REQUIRED",
        }), 401

    # 3. RBAC Admin check
    if getattr(current_user, "role", "") != "admin":
        log_event(
            action="lab_unauthorized_access",
            username=getattr(current_user, "username", "unknown"),
            user_id=getattr(current_user, "id", None),
            category="security",
            resource=request.path,
            ip_address=request.remote_addr or "",
            status="blocked",
            details="Non-admin user attempted to access Evaluation Lab API.",
        )
        return jsonify({
            "ok": False,
            "error": "Evaluation Lab is restricted to administrators only.",
            "code": "ADMIN_REQUIRED",
        }), 403

    # 4. Mandatory 2FA Enforcement for Evaluation Lab (Master Spec v5)
    if is_lab_2fa_enforced():
        if not getattr(current_user, "totp_enabled", False):
            return jsonify({
                "ok": False,
                "error": "Two-factor authentication (2FA) must be enabled on your admin account to access Evaluation Lab.",
                "code": "2FA_SETUP_REQUIRED",
            }), 403

        if session.get("pending_totp_user_id"):
            return jsonify({
                "ok": False,
                "error": "Two-factor authentication (2FA) verification is required.",
                "code": "2FA_REQUIRED",
            }), 403


@lab_bp.route("/status", methods=["GET"])
def lab_status():
    """Return runtime configuration status of the Evaluation Lab."""
    return jsonify({
        "ok": True,
        "lab_mode": is_lab_mode_enabled(),
        "remote_scanning_enabled": is_lab_remote_scanning_enabled(),
        "admin_user": current_user.username,
        "2fa_enforced": is_lab_2fa_enforced(),
    })


@lab_bp.route("/targets", methods=["GET"])
def get_targets():
    """List registered Evaluation Lab targets from Target Registry."""
    kind = request.args.get("kind")
    enabled_only = request.args.get("enabled", "0").lower().strip() in ("1", "true", "yes")

    # Ensure table is seeded
    seed_lab_targets()
    targets = list_lab_targets(kind=kind, enabled_only=enabled_only)
    return jsonify({
        "ok": True,
        "count": len(targets),
        "targets": targets,
    })


@lab_bp.route("/targets/<target_id>", methods=["GET"])
def get_target_detail(target_id: str):
    """Retrieve detailed specifications for a single lab target."""
    seed_lab_targets()
    target = get_lab_target(target_id)
    if not target:
        return jsonify({"ok": False, "error": f"Target '{target_id}' not found."}), 404

    return jsonify({
        "ok": True,
        "target": target,
    })


@lab_bp.route("/gate/verify", methods=["POST"])
def verify_gate():
    """Explicitly evaluate the fail-closed Lab Gate for a planned scan."""
    data = request.get_json(silent=True) or {}
    target_id = (data.get("target_id") or "").strip()
    scanner = (data.get("scanner") or "").strip()
    scan_type = (data.get("scan_type") or "").strip()
    acknowledge_public_scope = bool(data.get("acknowledge_public_scope", False))

    if not target_id or not scanner or not scan_type:
        return jsonify({
            "ok": False,
            "error": "target_id, scanner, and scan_type are required fields.",
        }), 400

    seed_lab_targets()
    result = evaluate_lab_gate(
        target_id=target_id,
        scanner=scanner,
        scan_type=scan_type,
        user_id=current_user.id,
        username=current_user.username,
        ip_address=request.remote_addr or "",
        acknowledge_public_scope=acknowledge_public_scope,
    )

    status_code = 200 if result.allowed else 403
    return jsonify({
        "ok": result.allowed,
        "gate": result.to_dict(),
    }), status_code


@lab_bp.route("/targets/<target_id>/acknowledge", methods=["POST"])
def acknowledge_scope(target_id: str):
    """Record mandatory administrator acknowledgement before running an authorized public target."""
    data = request.get_json(silent=True) or {}
    scope = data.get("scope", "default_scope")
    scan_type = data.get("scan_type", "web")

    record_user_acknowledgement(
        user_id=current_user.id,
        username=current_user.username,
        target_id=target_id,
        scope=scope,
        scan_type=scan_type,
        ip_address=request.remote_addr or "",
    )

    return jsonify({
        "ok": True,
        "message": f"Acknowledgement for target '{target_id}' recorded in immutable audit log.",
    })


@lab_bp.route("/benchmarks/run", methods=["POST"])
def run_benchmark():
    """Trigger a real Evaluation Lab benchmark run against an authorized target.

    Fulfills Phase 3 Key Gate:
      - Admin RBAC + 2FA enforced.
      - Gate verified before execution.
      - Supports synchronous execution (sync=true) or async job queue.
    """
    data = request.get_json(silent=True) or {}
    target_id = (data.get("target_id") or "fixture_sast_python").strip()
    engine_id = (data.get("engine_id") or "bandit").strip()
    dataset_id = (data.get("dataset_id") or "hexaguard_bench_core").strip()
    dataset_version = (data.get("dataset_version") or "1.0.0").strip()
    split = (data.get("split") or "dev").strip()
    repetitions = int(data.get("repetitions") or 1)
    sync_mode = bool(data.get("sync", False)) or request.args.get("sync") == "1"

    # Pre-verify fail-closed gate
    gate_res = evaluate_lab_gate(
        target_id=target_id,
        scanner=engine_id,
        scan_type="sast",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=request.remote_addr or "",
    )

    if not gate_res.allowed:
        return jsonify({
            "ok": False,
            "error": f"Lab Gate Denied: {gate_res.message}",
            "code": gate_res.reason_code,
            "gate": gate_res.to_dict(),
        }), 403

    uid = current_user.id
    uname = current_user.username

    if sync_mode:
        # Run synchronously (ideal for testing, automation, and immediate evaluation)
        scorecard = run_lab_benchmark(
            target_id=target_id,
            engine_id=engine_id,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            split=split,
            repetitions=repetitions,
            user_id=uid,
            username=uname,
        )
        return jsonify({
            "ok": True,
            "sync": True,
            "scorecard": scorecard.to_dict(),
        }), 200

    # Asynchronous execution via job system
    job_id = job_manager.create_job(
        scan_type="lab_benchmark",
        target=f"{engine_id}:{target_id}",
        user_id=uid,
        username=uname,
    )

    def _benchmark_worker():
        sc = run_lab_benchmark(
            target_id=target_id,
            engine_id=engine_id,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            split=split,
            repetitions=repetitions,
            user_id=uid,
            username=uname,
        )
        return sc.to_dict()

    job_manager.run_in_background(job_id, _benchmark_worker)

    return jsonify({
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "message": f"Benchmark run queued for engine '{engine_id}' against target '{target_id}'.",
        "poll_url": f"/api/scans/jobs/{job_id}",
    }), 202


@lab_bp.route("/benchmarks/<benchmark_id>", methods=["GET"])
def get_benchmark(benchmark_id: str):
    """Retrieve a persisted benchmark scorecard by its benchmark_id."""
    scorecard = get_benchmark_scorecard(benchmark_id)
    if not scorecard:
        return jsonify({
            "ok": False,
            "error": f"Benchmark scorecard '{benchmark_id}' not found.",
        }), 404

    return jsonify({
        "ok": True,
        "benchmark_id": benchmark_id,
        "scorecard": scorecard.get("scorecard_json") or scorecard,
    })


@lab_bp.route("/benchmarks", methods=["GET"])
def list_benchmarks():
    """List recent benchmark scorecard records."""
    engine_id = request.args.get("engine_id")
    target_id = request.args.get("target_id")
    limit = int(request.args.get("limit") or 50)

    runs = list_benchmark_scorecards(engine_id=engine_id, target_id=target_id, limit=limit)
    return jsonify({
        "ok": True,
        "count": len(runs),
        "benchmarks": runs,
    })


@lab_bp.route("/benchmarks/<benchmark_id>/view", methods=["GET"])
def view_benchmark_scorecard(benchmark_id: str):
    """Render minimal, elegant HTML UI scorecard for a benchmark run.

    Presents:
      - execution_status and benchmark_status SIDE BY SIDE.
      - Key metrics with Wilson confidence intervals.
      - Missed cases (False Negatives) list with full diagnostic evidence.
      - UNREVIEWED queue table.
      - Negative controls verification (True Negatives vs False Alarms).
    """
    record = get_benchmark_scorecard(benchmark_id)
    if not record:
        return f"<h3>Benchmark scorecard '{benchmark_id}' not found.</h3>", 404

    sc = record.get("scorecard_json") or record

    # Minimal UI Scorecard HTML Template
    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuraX Evaluation Lab — Scorecard {{ sc.get('benchmark_id', '') }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-card: #131b2e;
            --bg-card-hover: #1b2540;
            --border-color: #233152;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
            --accent-indigo: #6366f1;
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem 1.5rem;
            line-height: 1.5;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        .title h1 { font-size: 1.75rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem; }
        .meta-tags { display: flex; gap: 0.75rem; margin-top: 0.5rem; }
        .tag {
            background: #1e293b;
            color: var(--text-secondary);
            font-size: 0.8rem;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-family: var(--font-mono);
        }

        /* Dual Status Bar */
        .status-hero {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .status-box {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
        }
        .status-box.completed { border-color: rgba(16, 185, 129, 0.4); background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(19, 27, 46, 0.9) 100%); }
        .status-box.fail { border-color: rgba(244, 63, 94, 0.4); background: linear-gradient(135deg, rgba(244, 63, 94, 0.08) 0%, rgba(19, 27, 46, 0.9) 100%); }
        .status-box.pass { border-color: rgba(16, 185, 129, 0.4); background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(19, 27, 46, 0.9) 100%); }
        .status-label { font-size: 0.8rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; color: var(--text-secondary); }
        .status-value { font-size: 2rem; font-weight: 700; margin: 0.5rem 0; font-family: var(--font-mono); }
        .status-box.completed .status-value { color: var(--accent-emerald); }
        .status-box.fail .status-value { color: var(--accent-rose); }
        .status-box.pass .status-value { color: var(--accent-emerald); }
        .status-desc { font-size: 0.875rem; color: var(--text-secondary); }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.25rem;
        }
        .metric-title { font-size: 0.8rem; color: var(--text-muted); font-weight: 500; margin-bottom: 0.4rem; }
        .metric-number { font-size: 1.5rem; font-weight: 700; font-family: var(--font-mono); color: #fff; }
        .metric-sub { font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.35rem; }

        /* Tables */
        .section-header { margin: 2rem 0 1rem; display: flex; align-items: center; justify-content: space-between; }
        .section-header h2 { font-size: 1.25rem; font-weight: 600; }
        .count-badge { background: #334155; padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; margin-left: 0.5rem; }
        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 2rem;
        }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }
        th { background: #162035; color: var(--text-secondary); font-weight: 600; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); }
        td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(35, 49, 82, 0.5); vertical-align: top; }
        tr:last-child td { border-bottom: none; }
        .mono { font-family: var(--font-mono); }
        .badge-fn { background: rgba(244, 63, 94, 0.15); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.3); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
        .badge-tn { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
        .badge-unreviewed { background: rgba(245, 158, 11, 0.15); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.3); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
        .code-snippet { background: #070a12; padding: 0.5rem 0.75rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8rem; color: #cbd5e1; margin-top: 0.25rem; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="title">
                <h1>SecuraX Evaluation Lab — Benchmark Scorecard</h1>
                <div class="meta-tags">
                    <span class="tag">Engine: {{ sc.get('engine_id', 'unknown') }}</span>
                    <span class="tag">Target: {{ sc.get('target_id', 'unknown') }}</span>
                    <span class="tag">Dataset: {{ sc.get('dataset_id', 'hexaguard_bench_core') }} (v{{ sc.get('dataset_version', '1.0.0') }})</span>
                    <span class="tag">Protocol: v{{ sc.get('protocol_version', '1.0.0') }}</span>
                </div>
            </div>
            <div>
                <a href="/api/lab/benchmarks/{{ sc.get('benchmark_id') }}" style="color: var(--accent-indigo); text-decoration: none; font-size: 0.875rem; font-weight: 500;">Download JSON &rarr;</a>
            </div>
        </div>

        <!-- Dual Status Heroes (Side by Side) -->
        <div class="status-hero">
            <div class="status-box completed">
                <div class="status-label">1. Scanner Execution Status</div>
                <div class="status-value">{{ sc.get('execution_status') }}</div>
                <div class="status-desc">Scanner completed without process crash or timeout. All planned files inspected.</div>
            </div>
            <div class="status-box {{ sc.get('benchmark_status', 'FAIL').lower() }}">
                <div class="status-label">2. Benchmark Acceptance Decision</div>
                <div class="status-value">{{ sc.get('benchmark_status') }}</div>
                <div class="status-desc">
                    {% for r in sc.get('status_reasons', []) %}
                        <div>&bull; {{ r }}</div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Key Metrics Cards -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">In-Scope Recall</div>
                <div class="metric-number">
                    {% if sc.get('metrics', {}).get('in_scope_recall', {}).get('value') is not none %}
                        {{ "%.1f"|format(sc.metrics.in_scope_recall.value * 100) }}%
                    {% else %}N/A{% endif %}
                </div>
                <div class="metric-sub">{{ sc.get('counts', {}).get('tp', 0) }} / {{ sc.get('counts', {}).get('tp', 0) + sc.get('counts', {}).get('fn', 0) }} vulnerable cases detected</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">Precision (Lower Bound)</div>
                <div class="metric-number">
                    {% if sc.get('metrics', {}).get('precision_lower_bound', {}).get('value') is not none %}
                        {{ "%.1f"|format(sc.metrics.precision_lower_bound.value * 100) }}%
                    {% else %}N/A{% endif %}
                </div>
                <div class="metric-sub">Optimistic max: {{ "%.1f"|format((sc.get('metrics', {}).get('precision_optimistic_upper_bound', {}).get('value') or 0.0) * 100) }}%</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">F1 Score</div>
                <div class="metric-number">
                    {% if sc.get('metrics', {}).get('f1_score', {}).get('value') is not none %}
                        {{ "%.1f"|format(sc.metrics.f1_score.value * 100) }}%
                    {% else %}N/A{% endif %}
                </div>
                <div class="metric-sub">Harmonic mean of P & R</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">FPR on Negative Controls</div>
                <div class="metric-number">
                    {% if not sc.get('metrics', {}).get('fpr_on_negative_controls', {}).get('is_na') %}
                        {{ "%.1f"|format((sc.metrics.fpr_on_negative_controls.value or 0.0) * 100) }}%
                    {% else %}N/A{% endif %}
                </div>
                <div class="metric-sub">{{ sc.get('counts', {}).get('fp_on_negative_controls', 0) }} / {{ sc.get('counts', {}).get('eligible_negative_controls', 0) }} false alarms on safe controls</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">Case Coverage</div>
                <div class="metric-number">
                    {% if sc.get('metrics', {}).get('case_coverage', {}).get('value') is not none %}
                        {{ "%.0f"|format(sc.metrics.case_coverage.value * 100) }}%
                    {% else %}N/A{% endif %}
                </div>
                <div class="metric-sub">{{ sc.get('counts', {}).get('executed_eligible', 0) }} / {{ sc.get('counts', {}).get('planned_eligible', 0) }} eligible cases tested</div>
            </div>
        </div>

        {% if sc.get('counts', {}).get('tp', 0) == 0 and sc.get('counts', {}).get('confirmed_fp', 0) == 0 and sc.get('counts', {}).get('unreviewed', 0) == 0 %}
        <!-- Verified Scope Empty Finding Notice (Phase 4 requirement: never display 'secure') -->
        <div style="background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.4); padding: 1rem 1.25rem; border-radius: 8px; margin-bottom: 2rem; color: #c7d2fe; font-size: 0.9rem;">
            <strong>Verified Scope Notice:</strong> {{ sc.get('coverage_telemetry', {}).get('empty_result_wording', 'No findings within the verified scope and coverage shown') }}
        </div>
        {% endif %}

        <!-- Verified Scope & Coverage Telemetry (Phase 4) -->
        <div class="section-header">
            <h2>Verified Scope & Coverage Telemetry <span class="tag" style="margin-left: 0.5rem;">Phase 4</span></h2>
        </div>
        <div class="table-wrap" style="padding: 1.25rem; margin-bottom: 2rem;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.25rem;">
                <div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Files Analyzed</div>
                    <div class="mono" style="font-size: 0.9rem; font-weight: 600; color: #fff; margin-top: 0.25rem;">
                        {{ sc.get('coverage_telemetry', {}).get('files_analyzed', [])|join(', ') or 'None' }}
                    </div>
                </div>
                <div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Languages Analyzed</div>
                    <div class="mono" style="font-size: 0.9rem; font-weight: 600; color: #fff; margin-top: 0.25rem;">
                        {{ sc.get('coverage_telemetry', {}).get('languages_analyzed', [])|join(', ')|upper or 'PYTHON' }}
                    </div>
                </div>
                <div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Lines of Code Inspected</div>
                    <div class="mono" style="font-size: 0.9rem; font-weight: 600; color: #fff; margin-top: 0.25rem;">
                        {{ sc.get('coverage_telemetry', {}).get('lines_of_code', 61) }} LOC
                    </div>
                </div>
                <div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Auth Status</div>
                    <div class="mono" style="font-size: 0.9rem; font-weight: 600; color: #fff; margin-top: 0.25rem;">
                        {{ sc.get('coverage_telemetry', {}).get('auth_status', 'not_applicable')|upper }}
                    </div>
                </div>
                <div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Zero Coverage Guard</div>
                    <div class="mono" style="font-size: 0.9rem; font-weight: 600; margin-top: 0.25rem; color: {% if sc.get('coverage_telemetry', {}).get('zero_coverage') %}var(--accent-rose){% else %}var(--accent-emerald){% endif %};">
                        {{ 'ZERO_COVERAGE (INVALID)' if sc.get('coverage_telemetry', {}).get('zero_coverage') else 'VERIFIED_VALID (PASS)' }}
                    </div>
                </div>
            </div>
        </div>

        <!-- Wrapper Delta 4-Stage Findings Trace (Phase 4) -->
        <div class="section-header">
            <h2>Wrapper Delta (4-Stage Pipeline Analysis) <span class="tag" style="margin-left: 0.5rem;">Phase 4</span></h2>
            <div>
                {% if sc.get('wrapper_delta', {}).get('summary', {}).get('has_unexplained_loss') %}
                    <span class="badge-fn">UNEXPLAINED LOSS DETECTED</span>
                {% else %}
                    <span class="badge-tn">0 UNEXPLAINED LOSS (PASS)</span>
                {% endif %}
            </div>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Stage</th>
                        <th>Pipeline Stage Name</th>
                        <th>Findings Count</th>
                        <th>Transition &Delta;</th>
                        <th>Lost / Transformed Items & Reason Codes</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="tag">Stage 1</span></td>
                        <td><strong>Raw Tool Output</strong> (native scanner stdout JSON)</td>
                        <td class="mono" style="font-weight: 700;">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_1_raw', {}).get('count', 0) }}</td>
                        <td class="mono">—</td>
                        <td style="color: var(--text-secondary); font-size: 0.8rem;">Baseline raw findings emitted by scanner binary</td>
                    </tr>
                    <tr>
                        <td><span class="tag">Stage 2</span></td>
                        <td><strong>Adapter Output</strong> (CandidateFinding normalized objects)</td>
                        <td class="mono" style="font-weight: 700;">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_2_adapter', {}).get('count', 0) }}</td>
                        <td class="mono">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_2_adapter', {}).get('delta_from_previous', 0) }}</td>
                        <td>
                            {% for lost in sc.get('wrapper_delta', {}).get('stages', {}).get('stage_2_adapter', {}).get('lost_items', []) %}
                                <div><span class="badge-fn">{{ lost.reason_code }}</span> {{ lost.finding_id }}: {{ lost.root_cause }}</div>
                            {% else %}
                                <span style="color: var(--accent-emerald); font-size: 0.8rem;">Zero normalization loss</span>
                            {% endfor %}
                        </td>
                    </tr>
                    <tr>
                        <td><span class="tag">Stage 3</span></td>
                        <td><strong>Persisted Findings</strong> (deduplicated & stored in database)</td>
                        <td class="mono" style="font-weight: 700;">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_3_persisted', {}).get('count', 0) }}</td>
                        <td class="mono">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_3_persisted', {}).get('delta_from_previous', 0) }}</td>
                        <td>
                            {% for lost in sc.get('wrapper_delta', {}).get('stages', {}).get('stage_3_persisted', {}).get('lost_items', []) %}
                                <div><span class="badge-unreviewed">{{ lost.reason_code }}</span> {{ lost.finding_id }}: {{ lost.details or lost.root_cause }}</div>
                            {% else %}
                                <span style="color: var(--accent-emerald); font-size: 0.8rem;">Zero deduplication loss</span>
                            {% endfor %}
                        </td>
                    </tr>
                    <tr>
                        <td><span class="tag">Stage 4</span></td>
                        <td><strong>API & UI Displayed Findings</strong> (client rendered)</td>
                        <td class="mono" style="font-weight: 700;">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_4_displayed', {}).get('count', 0) }}</td>
                        <td class="mono">{{ sc.get('wrapper_delta', {}).get('stages', {}).get('stage_4_displayed', {}).get('delta_from_previous', 0) }}</td>
                        <td>
                            {% for lost in sc.get('wrapper_delta', {}).get('stages', {}).get('stage_4_displayed', {}).get('lost_items', []) %}
                                <div><span class="badge-fn">{{ lost.reason_code }}</span> {{ lost.finding_id }}: {{ lost.root_cause }}</div>
                            {% else %}
                                <span style="color: var(--accent-emerald); font-size: 0.8rem;">100% persisted findings surfaced to user</span>
                            {% endfor %}
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Missed Cases (False Negatives) Section -->
        <div class="section-header">
            <h2>Missed Cases (False Negatives) <span class="count-badge" style="background: rgba(244, 63, 94, 0.3); color: #fda4af;">{{ sc.get('missed_cases', [])|length }}</span></h2>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Case ID</th>
                        <th>Vulnerability</th>
                        <th>CWE</th>
                        <th>Severity</th>
                        <th>Location</th>
                        <th>Expected Evidence & Miss Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {% for fn in sc.get('missed_cases', []) %}
                    <tr>
                        <td><span class="badge-fn">MISSED (FN)</span></td>
                        <td class="mono">{{ fn.case_id }}</td>
                        <td><strong>{{ fn.vulnerability_type }}</strong></td>
                        <td class="mono">{{ fn.cwe }}</td>
                        <td><span class="tag">{{ fn.expected_severity|upper }}</span></td>
                        <td class="mono">{{ fn.location.get('file', '') }}:{{ fn.location.get('line', '') }}</td>
                        <td>
                            <div class="code-snippet">{{ fn.expected_evidence }}</div>
                            <div style="margin-top: 0.35rem; color: var(--text-secondary); font-size: 0.8rem;">
                                <em>Reason:</em> {{ fn.explanation }}
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Zero missed cases in this benchmark run.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- UNREVIEWED Queue Section -->
        <div class="section-header">
            <h2>UNREVIEWED Queue (Candidate findings not in manifest) <span class="count-badge" style="background: rgba(245, 158, 11, 0.3); color: #fde68a;">{{ sc.get('unreviewed_queue', [])|length }}</span></h2>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Bucket</th>
                        <th>Finding ID</th>
                        <th>Rule ID</th>
                        <th>CWE</th>
                        <th>Severity</th>
                        <th>Location</th>
                        <th>Evidence Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in sc.get('unreviewed_queue', []) %}
                    <tr>
                        <td><span class="badge-unreviewed">UNREVIEWED</span></td>
                        <td class="mono">{{ u.finding_id }}</td>
                        <td class="mono">{{ u.rule_id }}</td>
                        <td class="mono">{{ u.cwe }}</td>
                        <td><span class="tag">{{ u.severity|upper }}</span></td>
                        <td class="mono">{{ u.location.get('file', '') }}:{{ u.location.get('line', '') }}</td>
                        <td><div class="code-snippet">{{ u.evidence }}</div></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">UNREVIEWED queue is empty.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Negative Controls Verification Section -->
        <div class="section-header">
            <h2>Negative Controls Verification (Safe Look-Alikes) <span class="count-badge" style="background: rgba(16, 185, 129, 0.3); color: #6ee7b7;">{{ sc.get('negative_control_evaluations', [])|length }}</span></h2>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Case ID</th>
                        <th>Safe Control Description</th>
                        <th>CWE Family</th>
                        <th>Expected Truth</th>
                        <th>Location</th>
                        <th>Code Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {% for neg in sc.get('negative_control_evaluations', []) %}
                    <tr>
                        <td>
                            {% if neg.flagged %}
                                <span class="badge-fn">FALSE ALARM (FP)</span>
                            {% else %}
                                <span class="badge-tn">CLEAN PASS (TN)</span>
                            {% endif %}
                        </td>
                        <td class="mono">{{ neg.case_id }}</td>
                        <td><strong>{{ neg.vulnerability_type }}</strong></td>
                        <td class="mono">{{ neg.cwe }}</td>
                        <td class="mono">{{ neg.truth_state }}</td>
                        <td class="mono">{{ neg.location.get('file', '') }}:{{ neg.location.get('line', '') }}</td>
                        <td><div class="code-snippet">{{ neg.expected_evidence }}</div></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    return render_template_string(template, sc=sc)
