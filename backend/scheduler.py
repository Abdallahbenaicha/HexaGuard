"""SecuraX — Background Scheduler Worker for Scheduled Scans.

Polls the database for active scheduled scans where next_run_at <= now,
advances next_run_at according to cron_expr, and launches the scan execution
via job_manager with global concurrency control.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import database as db
import job_manager

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_scheduler_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


def compute_next_run(cron_expr: str, base_dt: datetime | None = None) -> str:
    """Compute the next run ISO timestamp based on cadence."""
    base = base_dt or datetime.now(timezone.utc)
    expr = (cron_expr or "daily").strip().lower()

    if expr == "weekly":
        delta = timedelta(days=7)
    elif expr == "monthly":
        delta = timedelta(days=30)
    elif expr == "daily":
        delta = timedelta(days=1)
    elif expr.startswith("minutes:") or expr.startswith("every_minutes:"):
        try:
            mins = int(expr.split(":")[-1])
            delta = timedelta(minutes=max(1, mins))
        except ValueError:
            delta = timedelta(days=1)
    else:
        delta = timedelta(days=1)

    return (base + delta).isoformat()


def _execute_scan_worker(scan_type: str, target: str, user_id: int, username: str, app=None) -> dict[str, Any]:
    """Execute scan logic based on scan_type and store report."""
    def _run():
        res: dict[str, Any] = {"scan_type": scan_type, "target": target, "vulnerabilities": []}
        try:
            if scan_type == "web":
                from scanners.web_scanner import run_web_scan
                res = run_web_scan(target, cve_check=True, ssl_check=True)
            elif scan_type == "network":
                from scanners.netscan_scanner import run_nmap_scan
                res = run_nmap_scan(target)
            elif scan_type == "dast":
                from scanners.dast_scanner import run_dast_scan
                res = run_dast_scan(target)
            elif scan_type == "ssl":
                from scanners.ssl_scanner import run_ssl_scan
                res = run_ssl_scan(target)
            elif scan_type in ("server", "server_ext"):
                from scanners.server_ext import run_server_scan
                res = run_server_scan(target)
            elif scan_type == "dependencies":
                from scanners.dep_scanner import run_dep_scan
                res = run_dep_scan(target)
            else:
                logger.warning("Unknown scheduled scan_type=%s; defaulting to web", scan_type)
                from scanners.web_scanner import run_web_scan
                res = run_web_scan(target)
        except Exception as exc:
            logger.error("Error executing scheduled %s scan on %s: %s", scan_type, target, exc)
            res["error"] = str(exc)

        # Calculate risk score
        vulns = res.get("vulnerabilities", [])
        score = 0.0
        for v in vulns:
            sev = str(v.get("severity", "low")).lower()
            if sev == "critical":
                score += 3.5
            elif sev == "high":
                score += 2.0
            elif sev == "medium":
                score += 1.0
            else:
                score += 0.3
        score = min(10.0, round(score, 1))

        # Store report
        token = db.store_report(
            result=res,
            risk_score=score,
            original_content=None,
            user_id=user_id,
            username=username,
        )
        return {
            "status": "completed",
            "report_token": token,
            "findings_count": len(vulns),
            "risk_score": score,
        }

    if app is not None:
        with app.app_context():
            return _run()
    return _run()


def dispatch_scheduled_scan(sched: dict[str, Any], app=None) -> str:
    """Create a tracked job and run it in background with concurrency semaphore protection."""
    sched_id = sched["id"]
    user_id = sched["user_id"]
    username = sched.get("username", "system")
    scan_type = sched.get("scan_type", "web")
    target = sched.get("target", "")

    # Create job in job_manager
    job_id = job_manager.create_job(
        scan_type=scan_type,
        target=target,
        user_id=user_id,
        username=username,
    )

    db.log_event(
        "scheduled_scan_dispatched",
        username=username,
        user_id=user_id,
        category="scheduler",
        resource=target,
        details=f"sched_id={sched_id} job_id={job_id} type={scan_type}",
    )

    def _worker():
        return _execute_scan_worker(scan_type, target, user_id, username, app=app)

    job_manager.run_in_background(job_id, _worker)
    return job_id


def run_scheduler_tick(app=None) -> list[str]:
    """One scheduler check cycle: inspects due scans and dispatches them."""
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    due_scans = db.get_due_scheduled_scans(now_iso)
    dispatched_job_ids: list[str] = []

    for sched in due_scans:
        sched_id = sched["id"]
        cron_expr = sched.get("cron_expr", "daily")
        next_run = compute_next_run(cron_expr, base_dt=now_dt)

        # Update last_run and next_run to prevent duplicate execution in next tick
        db.update_scheduled_scan_run(sched_id, last_run_at=now_iso, next_run_at=next_run)

        # Dispatch execution
        job_id = dispatch_scheduled_scan(sched, app=app)
        dispatched_job_ids.append(job_id)

    return dispatched_job_ids


def _scheduler_loop(app, interval_seconds: float):
    logger.info("Scheduler worker thread started (interval=%ss)", interval_seconds)
    while not _stop_event.is_set():
        try:
            run_scheduler_tick(app=app)
        except Exception as exc:
            logger.error("Error in scheduler tick: %s", exc, exc_info=True)
        _stop_event.wait(timeout=interval_seconds)
    logger.info("Scheduler worker thread stopped.")


def start_scheduler(app=None, interval_seconds: float = 15.0) -> bool:
    """Start background scheduler thread if not already running."""
    global _scheduler_thread
    with _thread_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        _stop_event.clear()
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop,
            args=(app, interval_seconds),
            daemon=True,
            name="securax-scheduler",
        )
        _scheduler_thread.start()
        return True


def stop_scheduler(timeout: float = 3.0) -> None:
    """Signal background scheduler to stop and wait for termination."""
    global _scheduler_thread
    with _thread_lock:
        _stop_event.set()
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            _scheduler_thread.join(timeout=timeout)
            _scheduler_thread = None


def is_scheduler_running() -> bool:
    """Return True if background scheduler thread is alive."""
    return _scheduler_thread is not None and _scheduler_thread.is_alive()
