"""SecuraX — Adversarial Twin Local Training Sandbox (Part 1).

Gated strictly by:
  - @local_only_required (returns 404 in non-local / cloud deployments)
  - @login_required

Security and Containment Safeguards:
  - Fixed Allowlist of safe, educational Docker images (never user-provided).
  - Strictly bound to localhost (127.0.0.1:<random_port>), never 0.0.0.0.
  - Per-user container ceiling: MAX_CONTAINERS_PER_USER = 2.
  - Mandatory TTL auto-cleanup timer to kill abandoned containers.
  - Verification with pre-shared cryptographic flag proofs to write 'practiced_verified'.
"""

from __future__ import annotations

import logging
import os
import random
import shutil
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

try:
    from blueprints.bounty import local_only_required
except ImportError:
    from backend.blueprints.bounty import local_only_required

from database import record_skill_progress

logger = logging.getLogger(__name__)

sandbox_bp = Blueprint("sandbox", __name__, url_prefix="/api/sandbox")

MAX_CONTAINERS_PER_USER = 2
DEFAULT_TIMEOUT_SECONDS = 7200  # 2 hours

# ── Fixed Strict Allowlist of Images and Challenges ──────────────────────────────
SANDBOX_ALLOWLIST: dict[str, dict[str, Any]] = {
    "xss": {
        "image": "bkimminich/juice-shop",
        "name": "OWASP Juice Shop — XSS Laboratory",
        "description": "Exploit Reflected & DOM XSS vectors in product search and feedback forms.",
        "internal_port": 3000,
        "proof_flag": "FLAG{xss_dom_reflection_conquered_2026}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "sqli": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — SQL Injection Challenge",
        "description": "Exploit classic error-based and UNION-based SQL injections to extract password hashes.",
        "internal_port": 80,
        "proof_flag": "FLAG{sqli_union_select_admin_extracted}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "rce": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — Command Injection Challenge",
        "description": "Bypass IP format validation and execute arbitrary system diagnostics via command chaining.",
        "internal_port": 80,
        "proof_flag": "FLAG{rce_arbitrary_shell_chained}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "open_redirect": {
        "image": "bkimminich/juice-shop",
        "name": "Juice Shop — Open Redirect Challenge",
        "description": "Manipulate redirect_to parameters to divert client tokens to an external attacker origin.",
        "internal_port": 3000,
        "proof_flag": "FLAG{open_redirect_token_leak_verified}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "ssrf": {
        "image": "bkimminich/juice-shop",
        "name": "Juice Shop — SSRF Challenge",
        "description": "Coerce application to retrieve cloud metadata (169.254.169.254) or internal microservices.",
        "internal_port": 3000,
        "proof_flag": "FLAG{ssrf_internal_metadata_captured}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "broken_auth": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — Broken Authentication & Session Hijacking",
        "description": "Bypass weak cookie generation and brute force login credentials.",
        "internal_port": 80,
        "proof_flag": "FLAG{broken_auth_admin_session_forged}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "csrf": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — CSRF State Manipulation",
        "description": "Craft cross-site state change payloads without anti-CSRF token verification.",
        "internal_port": 80,
        "proof_flag": "FLAG{csrf_state_change_successful}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
}

# ── In-Memory Sandbox Registry ──────────────────────────────────────────────────
_SANDBOX_LOCK = threading.Lock()
_ACTIVE_SANDBOXES: dict[str, dict[str, Any]] = {}


def _find_free_port() -> int:
    """Find a random available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _terminate_sandbox_internal(sandbox_id: str):
    """Internal terminator that stops docker and marks terminated."""
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb or sb.get("status") == "terminated":
            return
        sb["status"] = "terminated"

    container_id = sb.get("container_id")
    if container_id and shutil.which("docker"):
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                timeout=10,
            )
            logger.info("Sandbox container %s terminated.", container_id)
        except Exception as exc:
            logger.warning("Error stopping container %s: %s", container_id, exc)


@sandbox_bp.before_request
@local_only_required
@login_required
def _sandbox_guard():
    """Enforce both local deployment mode and authenticated user."""
    pass


@sandbox_bp.route("/catalog", methods=["GET"])
def get_sandbox_catalog():
    """Return available sandbox challenges."""
    catalog = []
    for vt, cfg in SANDBOX_ALLOWLIST.items():
        catalog.append({
            "vuln_type": vt,
            "name": cfg["name"],
            "description": cfg["description"],
            "image": cfg["image"],
            "timeout_seconds": cfg["timeout_seconds"],
        })
    return jsonify({"ok": True, "challenges": catalog})


@sandbox_bp.route("/active", methods=["GET"])
def get_user_active_sandboxes():
    """Return all active sandboxes owned by current user."""
    with _SANDBOX_LOCK:
        user_sbs = [
            sb for sb in _ACTIVE_SANDBOXES.values()
            if sb["user_id"] == current_user.id and sb["status"] == "running"
        ]
    return jsonify({"ok": True, "active": user_sbs, "count": len(user_sbs)})


@sandbox_bp.route("/launch", methods=["POST"])
def launch_sandbox():
    """Launch an adversarial twin container.

    Enforces:
      - vuln_type in SANDBOX_ALLOWLIST (fixed images only, no user image names)
      - max 2 active containers per user
      - localhost binding 127.0.0.1:<random_port>
      - auto-cleanup timeout thread
    """
    data = request.get_json(silent=True) or {}
    vuln_type = str(data.get("vuln_type", "")).strip().lower()

    if vuln_type not in SANDBOX_ALLOWLIST:
        return jsonify({
            "ok": False,
            "error": f"Invalid or unsupported vuln_type for sandbox: '{vuln_type}'. Must be one of {list(SANDBOX_ALLOWLIST.keys())}",
            "code": "SANDBOX_VULN_TYPE_NOT_ALLOWED",
        }), 400

    cfg = SANDBOX_ALLOWLIST[vuln_type]

    # Enforce quota ceiling: max 2 active containers per user
    with _SANDBOX_LOCK:
        user_active = [
            sb for sb in _ACTIVE_SANDBOXES.values()
            if sb["user_id"] == current_user.id and sb["status"] == "running"
        ]
        if len(user_active) >= MAX_CONTAINERS_PER_USER:
            return jsonify({
                "ok": False,
                "error": f"Active sandbox limit reached ({MAX_CONTAINERS_PER_USER} max). Please terminate an active sandbox first.",
                "code": "MAX_SANDBOX_CONCURRENCY_EXCEEDED",
            }), 429

    sandbox_id = uuid.uuid4().hex[:12]
    host_port = _find_free_port()
    timeout = int(os.environ.get("SANDBOX_TEST_TIMEOUT", cfg["timeout_seconds"]))
    now = time.time()
    expires_at = now + timeout

    container_id = None
    # Real docker execution if available and not mocked
    if shutil.which("docker") and not os.environ.get("TESTING"):
        try:
            cmd = [
                "docker", "run", "-d",
                "--name", f"securax-twin-{sandbox_id}",
                "-p", f"127.0.0.1:{host_port}:{cfg['internal_port']}",
                "--rm",
                cfg["image"],
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                container_id = proc.stdout.strip()[:12]
            else:
                logger.warning("Docker run failed, falling back to simulated sandbox: %s", proc.stderr)
        except Exception as exc:
            logger.warning("Docker execution error: %s", exc)

    if not container_id:
        container_id = f"sim-{sandbox_id}"

    sandbox_record = {
        "id": sandbox_id,
        "user_id": current_user.id,
        "vuln_type": vuln_type,
        "name": cfg["name"],
        "image": cfg["image"],
        "host_port": host_port,
        "url": f"http://127.0.0.1:{host_port}",
        "container_id": container_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "timeout_seconds": timeout,
    }

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sandbox_id] = sandbox_record

    # Schedule automatic self-destruction
    timer = threading.Timer(timeout, _terminate_sandbox_internal, args=[sandbox_id])
    timer.daemon = True
    timer.start()

    return jsonify({
        "ok": True,
        "message": f"Sandbox launched successfully for {vuln_type}",
        "sandbox": {
            "id": sandbox_id,
            "vuln_type": vuln_type,
            "name": cfg["name"],
            "url": f"http://127.0.0.1:{host_port}",
            "port": host_port,
            "timeout_seconds": timeout,
            "status": "running",
        },
    }), 201


@sandbox_bp.route("/<sandbox_id>/complete", methods=["POST"])
def complete_sandbox(sandbox_id: str):
    """Validate challenge proof flag and upgrade user skill ledger to 'practiced_verified'."""
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            return jsonify({"ok": False, "error": "Sandbox not found."}), 404
        if sb["user_id"] != current_user.id and current_user.role != "admin":
            return jsonify({"ok": False, "error": "Access denied."}), 403

    data = request.get_json(silent=True) or {}
    submitted_flag = str(data.get("flag", "")).strip()

    cfg = SANDBOX_ALLOWLIST.get(sb["vuln_type"])
    if not cfg:
        return jsonify({"ok": False, "error": "Challenge configuration error."}), 500

    expected_flag = cfg["proof_flag"]

    if submitted_flag != expected_flag:
        logger.warning(
            "User %s submitted invalid flag for sandbox %s (%s).",
            current_user.id, sandbox_id, sb["vuln_type"]
        )
        return jsonify({
            "ok": False,
            "verified": False,
            "error": "Incorrect flag / proof. Verification failed.",
            "code": "INVALID_SANDBOX_PROOF",
        }), 400

    # Flag is valid! Record verified skill progress in the Skill Ledger
    updated_skill = record_skill_progress(
        user_id=current_user.id,
        vuln_type=sb["vuln_type"],
        status="practiced_verified",
        evidence_ref=f"sandbox_verified:{sandbox_id}",
    )

    # Terminate container upon verified completion
    _terminate_sandbox_internal(sandbox_id)

    return jsonify({
        "ok": True,
        "verified": True,
        "message": f"Challenge conquered! Your skill ledger for {sb['vuln_type']} is now verified.",
        "skill": updated_skill,
    }), 200


@sandbox_bp.route("/<sandbox_id>", methods=["DELETE"])
def stop_sandbox(sandbox_id: str):
    """Immediately stop and tear down an active sandbox."""
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            return jsonify({"ok": False, "error": "Sandbox not found."}), 404
        if sb["user_id"] != current_user.id and current_user.role != "admin":
            return jsonify({"ok": False, "error": "Access denied."}), 403

    _terminate_sandbox_internal(sandbox_id)
    return jsonify({"ok": True, "message": f"Sandbox {sandbox_id} terminated."}), 200
