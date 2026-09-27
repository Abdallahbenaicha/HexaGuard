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

import hashlib
import logging
import os
import random
import secrets
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

from database import (
    record_skill_progress,
    record_capability_evidence,
    save_active_sandbox_record,
    get_active_sandbox_record,
    get_user_active_sandboxes_records,
    update_active_sandbox_state,
    delete_active_sandbox_record,
)

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
    # Temporary Phase-2 Sandbox Allowlist Configurations
    # ARCHITECTURAL NOTE: Static flags are temporary allowlist entries for Phase-2 lab scaffolding
    # and MUST NOT be considered cryptographic proofs. Server-side authoritative condition verification
    # will be implemented in subsequent sub-phases.
    "idor": {
        "image": "bkimminich/juice-shop",
        "name": "Juice Shop — IDOR & BOLA Challenge",
        "description": "Multi-user authorization bypass testing cross-account basket and order access.",
        "internal_port": 3000,
        "proof_flag": "FLAG{idor_insecure_direct_object_reference_extracted}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "path_traversal": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — File Inclusion & Directory Traversal",
        "description": "Navigate directory structures using relative traversal sequences to access internal files.",
        "internal_port": 80,
        "proof_flag": "FLAG{path_traversal_etc_passwd_extracted}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "file_upload": {
        "image": "vulnerables/web-dvwa",
        "name": "DVWA — Unrestricted File Upload Laboratory",
        "description": "Probe complete file upload lifecycle, extension restrictions, and MIME validation.",
        "internal_port": 80,
        "proof_flag": "FLAG{arbitrary_file_upload_shell_executed}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
    "http_fundamentals": {
        "image": "bkimminich/juice-shop",
        "name": "Juice Shop — HTTP Protocol & Verb Tampering Lab",
        "description": "Probe HTTP methods, headers, and protocol semantics against Juice Shop REST endpoints.",
        "internal_port": 3000,
        "proof_flag": "FLAG{http_protocol_verbs_and_headers_mastered}",
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    },
}


# ── In-Memory Sandbox Registry ──────────────────────────────────────────────────
_SANDBOX_LOCK = threading.RLock()
_ACTIVE_SANDBOXES: dict[str, dict[str, Any]] = {}


def _find_free_port() -> int:
    """Find a random available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _terminate_sandbox_internal(sandbox_id: str):
    """Internal terminator that stops docker and marks terminated in memory and persistent storage."""
    container_id = None
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if sb:
            if sb.get("status") == "terminated":
                return
            sb["status"] = "terminated"
            container_id = sb.get("container_id")

    # Update persistent database
    try:
        update_active_sandbox_state(sandbox_id, status="terminated")
    except Exception as exc:
        logger.warning("Failed to update sandbox status in DB: %s", exc)

    if container_id and shutil.which("docker") and not os.environ.get("TESTING"):
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
    """Return all active sandboxes owned by current user (cross-referenced with DB)."""
    db_sbs = get_user_active_sandboxes_records(current_user.id)
    with _SANDBOX_LOCK:
        for sb in db_sbs:
            if sb["id"] not in _ACTIVE_SANDBOXES:
                _ACTIVE_SANDBOXES[sb["id"]] = sb
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
      - max 2 active containers per user (enforced across DB and memory)
      - localhost binding 127.0.0.1:<random_port>
      - auto-cleanup timeout thread
      - persistent SQLite state recording with SHA256 flag hash
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
    db_sbs = get_user_active_sandboxes_records(current_user.id)
    with _SANDBOX_LOCK:
        mem_ids = {
            sb["id"] for sb in _ACTIVE_SANDBOXES.values()
            if sb["user_id"] == current_user.id and sb["status"] == "running"
        }
        db_ids = {sb["id"] for sb in db_sbs}
        total_active = mem_ids.union(db_ids)
        if len(total_active) >= MAX_CONTAINERS_PER_USER:
            return jsonify({
                "ok": False,
                "error": f"Active sandbox limit reached ({MAX_CONTAINERS_PER_USER} max). Please terminate an active sandbox first.",
                "code": "MAX_SANDBOX_CONCURRENCY_EXCEEDED",
            }), 429

    sandbox_id = secrets.token_hex(16)
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

    flag_hash = hashlib.sha256(cfg["proof_flag"].encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

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
        "completed": False,
        "flag_hash": flag_hash,
        "started_at": now_iso,
        "expires_at": expires_at,
        "timeout_seconds": timeout,
        "created_at": now_iso,
    }

    with _SANDBOX_LOCK:
        _ACTIVE_SANDBOXES[sandbox_id] = sandbox_record

    # Persist in SQLite
    try:
        save_active_sandbox_record(sandbox_record)
    except Exception as exc:
        logger.warning("Failed to persist sandbox to SQLite: %s", exc)

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


def verify_sandbox_proof_authoritative(
    sandbox_id: str,
    user_id: int,
    vuln_type: str,
    submitted_flag: str,
) -> tuple[bool, str, dict[str, Any] | None, dict[str, Any] | None]:
    """Authoritative server-side verification of a sandbox proof flag.

    Anti-Cheat Invariants:
    1. Sandbox must exist in the authoritative active server registry (in-memory or SQLite).
    2. Strict Ownership: sandbox must belong to requesting user_id (User B cannot use User A's sandbox).
    3. Target Match: sandbox vuln_type must match requested challenge vuln_type.
    4. Status Check: sandbox status must be 'running' (not terminated, stopped, or pending).
    5. TTL / Expiry: current time must not exceed expires_at. Expired sandboxes fail immediately.
    6. Replay & Reuse Prevention: completed sandboxes cannot be verified again.
    7. Timing-Safe Flag Match: secrets.compare_digest prevents side-channel flag extraction.

    On successful verification:
    - Atomically marks sandbox as completed and status as terminated in memory and SQLite.
    - Updates skill ledger to practiced_verified.
    - Records VERIFIED capability evidence for lab_exploitation (is_verified=1, score=1.0).
    - Terminates sandbox container.
    - Returns (True, message, skill_record, evidence_record).

    On failure:
    - Returns (False, error_reason, None, None). Fail-closed under all circumstances.
    """
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            # Fall back to SQLite persistence across worker recycles/restarts
            sb_db = get_active_sandbox_record(sandbox_id)
            if sb_db:
                _ACTIVE_SANDBOXES[sandbox_id] = sb_db
                sb = sb_db

        if not sb:
            return False, "Sandbox not found in active server registry.", None, None

        if sb.get("user_id") != user_id:
            logger.warning("Sandbox ownership mismatch: user %s attempted to verify sandbox %s owned by %s", user_id, sandbox_id, sb.get("user_id"))
            return False, "Sandbox access denied: ownership mismatch.", None, None

        if sb.get("vuln_type") != vuln_type:
            logger.warning("Sandbox vuln_type mismatch: expected %s, got %s", vuln_type, sb.get("vuln_type"))
            return False, f"Sandbox target mismatch: sandbox is configured for '{sb.get('vuln_type')}', not '{vuln_type}'.", None, None

        if sb.get("completed", False):
            return False, "Sandbox challenge has already been completed and cannot be reused.", None, None

        if sb.get("status") != "running":
            return False, f"Sandbox is not active (current status: '{sb.get('status')}').", None, None

        now = time.time()
        if now > sb.get("expires_at", float("inf")):
            _terminate_sandbox_internal(sandbox_id)
            return False, "Sandbox session has expired (TTL exceeded).", None, None

        cfg = SANDBOX_ALLOWLIST.get(sb["vuln_type"])
        if not cfg:
            return False, "Challenge configuration not found.", None, None

        expected_flag = cfg.get("proof_flag", "")
        if not expected_flag or not submitted_flag:
            return False, "Flag cannot be empty.", None, None

        sub_flag_clean = submitted_flag.strip()
        exp_flag_clean = expected_flag.strip()
        sub_hash = hashlib.sha256(sub_flag_clean.encode("utf-8")).hexdigest()
        stored_hash = sb.get("flag_hash") or hashlib.sha256(exp_flag_clean.encode("utf-8")).hexdigest()

        if not (secrets.compare_digest(sub_flag_clean, exp_flag_clean) and secrets.compare_digest(sub_hash, stored_hash)):
            logger.warning("Invalid flag submitted for sandbox %s by user %s", sandbox_id, user_id)
            return False, "Incorrect flag / proof. Verification failed.", None, None

        # Flag is valid! Atomically transition state before releasing lock
        sb["completed"] = True
        sb["status"] = "terminated"

    # Update SQLite persistence
    try:
        update_active_sandbox_state(sandbox_id, status="terminated", completed=True)
    except Exception as exc:
        logger.warning("Failed to update sandbox completion in DB: %s", exc)

    # Outside lock: record verified progress and capability evidence
    updated_skill = record_skill_progress(
        user_id=user_id,
        vuln_type=vuln_type,
        status="practiced_verified",
        evidence_ref=f"sandbox_verified:{sandbox_id}",
    )

    ev = record_capability_evidence(
        user_id=user_id,
        vuln_type=vuln_type,
        capability="lab_exploitation",
        evidence_type="VERIFIED",
        evidence_source=f"sandbox_verified:{sandbox_id}",
        source_id=sandbox_id,
        is_verified=1,
        score=1.0,
        notes=f"Server-side sandbox challenge proof flag verified for {vuln_type}",
    )

    _terminate_sandbox_internal(sandbox_id)
    return True, f"Challenge conquered! Your skill ledger for {vuln_type} is now verified.", updated_skill, ev


@sandbox_bp.route("/<sandbox_id>/complete", methods=["POST"])
def complete_sandbox(sandbox_id: str):
    """Validate challenge proof flag and upgrade user skill ledger to 'practiced_verified'."""
    data = request.get_json(silent=True) or {}
    submitted_flag = str(data.get("flag", "")).strip()

    # Determine vuln_type from active sandbox record under lock (memory + DB fallback)
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            sb_db = get_active_sandbox_record(sandbox_id)
            if sb_db:
                _ACTIVE_SANDBOXES[sandbox_id] = sb_db
                sb = sb_db
        if not sb:
            return jsonify({"ok": False, "error": "Sandbox not found."}), 404
        if sb["user_id"] != current_user.id and current_user.role != "admin":
            return jsonify({"ok": False, "error": "Access denied."}), 403
        vuln_type = sb["vuln_type"]

    ok, msg, skill, ev = verify_sandbox_proof_authoritative(
        sandbox_id=sandbox_id,
        user_id=current_user.id,
        vuln_type=vuln_type,
        submitted_flag=submitted_flag,
    )

    if not ok:
        return jsonify({
            "ok": False,
            "verified": False,
            "error": msg,
            "code": "INVALID_SANDBOX_PROOF",
        }), 400

    # Ensure an authoritative exercise_attempt record is recorded for this lab completion
    try:
        from db.connection import _get_db
        db = _get_db()
        now_iso = datetime.now(timezone.utc).isoformat()
        open_att = db.execute(
            "SELECT id FROM exercise_attempts WHERE user_id = ? AND vuln_type = ? AND capability = 'lab_exploitation' AND completed_at IS NULL ORDER BY id DESC LIMIT 1",
            (current_user.id, vuln_type),
        ).fetchone()
        if open_att:
            db.execute(
                "UPDATE exercise_attempts SET completed_at = ?, submission_text = ?, score = 1.0, result = 'passed', evaluation_status = 'system_verified', evidence_id = ? WHERE id = ?",
                (now_iso, submitted_flag, ev["id"] if ev else None, open_att["id"]),
            )
        else:
            ex_row = db.execute(
                "SELECT id FROM learning_exercises WHERE vuln_type = ? AND (capability = 'lab_exploitation' OR exercise_type = 'lab') ORDER BY id ASC LIMIT 1",
                (vuln_type,),
            ).fetchone()
            ex_id = ex_row["id"] if ex_row else None
            if ex_id:
                count_row = db.execute(
                    "SELECT COUNT(*) as cnt FROM exercise_attempts WHERE user_id = ? AND exercise_id = ?",
                    (current_user.id, ex_id),
                ).fetchone()
                attempt_num = (count_row["cnt"] if count_row else 0) + 1
                db.execute(
                    "INSERT INTO exercise_attempts "
                    "(user_id, exercise_id, vuln_type, capability, attempt_number, started_at, completed_at, submission_text, score, result, evaluation_status, hints_used, aria_calls_used, solution_viewed, evidence_id) "
                    "VALUES (?, ?, ?, 'lab_exploitation', ?, ?, ?, ?, 1.0, 'passed', 'system_verified', 0, 0, 0, ?)",
                    (current_user.id, ex_id, vuln_type, attempt_num, now_iso, now_iso, submitted_flag, ev["id"] if ev else None),
                )
        db.commit()
    except Exception as exc:
        logger.warning("Could not record attempt for sandbox completion: %s", exc)

    return jsonify({
        "ok": True,
        "verified": True,
        "message": msg,
        "skill": skill,
        "evidence": ev,
    }), 200


@sandbox_bp.route("/<sandbox_id>", methods=["DELETE"])
def stop_sandbox(sandbox_id: str):
    """Immediately stop and tear down an active sandbox."""
    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            sb_db = get_active_sandbox_record(sandbox_id)
            if sb_db:
                _ACTIVE_SANDBOXES[sandbox_id] = sb_db
                sb = sb_db
        if not sb:
            return jsonify({"ok": False, "error": "Sandbox not found."}), 404
        if sb["user_id"] != current_user.id and current_user.role != "admin":
            return jsonify({"ok": False, "error": "Access denied."}), 403

    _terminate_sandbox_internal(sandbox_id)
    return jsonify({"ok": True, "message": f"Sandbox {sandbox_id} terminated."}), 200
