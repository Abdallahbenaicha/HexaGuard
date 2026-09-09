"""SecuraX — background scan job manager with SQLite persistence.

Jobs are written to the scan_jobs table on every state change, so they
survive server restarts.  An in-memory mirror is kept for fast reads.
"""

import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

import database as db

logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_TTL_MINUTES = 60

# Concurrency cap (default 3 simultaneous scans to prevent memory/CPU starvation)
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
_scan_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def set_concurrency_limit(limit: int) -> None:
    """Dynamically set concurrency limit (useful for testing or scaling)."""
    global MAX_CONCURRENT_SCANS, _scan_semaphore
    MAX_CONCURRENT_SCANS = max(1, limit)
    _scan_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def get_active_jobs_stats() -> dict:
    """Return count of currently running and queued jobs."""
    with _lock:
        running = sum(1 for j in _jobs.values() if j.get("status") == "running")
        queued = sum(1 for j in _jobs.values() if j.get("status") == "queued")
    return {"running": running, "queued": queued, "max_concurrent": MAX_CONCURRENT_SCANS}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _purge_old() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=_TTL_MINUTES)
    to_del = [
        jid for jid, j in _jobs.items()
        if j["status"] in ("done", "error")
        and j.get("completed_at")
        and datetime.fromisoformat(j["completed_at"]) < cutoff
    ]
    for jid in to_del:
        del _jobs[jid]


def _save(job: dict) -> None:
    """Persist job to SQLite (best-effort — never crash the scan on DB error)."""
    try:
        db.upsert_job(job)
    except Exception as exc:
        logger.warning("job persist failed: %s", exc)


def create_job(scan_type: str, target: str, user_id: int, username: str) -> str:
    job_id = str(uuid.uuid4())
    job = {
        "job_id":       job_id,
        "scan_type":    scan_type,
        "target":       target,
        "user_id":      user_id,
        "username":     username,
        "status":       "queued",
        "progress":     0,
        "message":      "Queued…",
        "result":       None,
        "error":        None,
        "report_token": None,
        "started_at":   _now(),
        "completed_at": None,
    }
    with _lock:
        _purge_old()
        _jobs[job_id] = job
    _save(job)
    return job_id


def update_job(job_id: str, **kwargs) -> None:
    with _lock:
        if job_id not in _jobs:
            return
        _jobs[job_id].update(kwargs)
        job = dict(_jobs[job_id])
    _save(job)


def get_job(job_id: str) -> dict | None:
    with _lock:
        j = _jobs.get(job_id)
        if j:
            return dict(j)
    # Fallback to DB (e.g. after restart)
    return db.get_job_from_db(job_id)


def get_user_jobs(user_id: int) -> list[dict]:
    with _lock:
        mem = [dict(j) for j in _jobs.values() if j["user_id"] == user_id]
    mem_ids = {j["job_id"] for j in mem}
    # Merge with DB (catches jobs from previous process lifetimes)
    try:
        db_jobs = [j for j in db.get_user_jobs_from_db(user_id) if j["job_id"] not in mem_ids]
    except Exception:
        db_jobs = []
    merged = mem + db_jobs
    merged.sort(key=lambda j: j.get("started_at", ""), reverse=True)
    return merged[:20]


def dismiss_job(job_id: str, user_id: int) -> bool:
    """Remove a completed/error job from memory and DB. Returns True if removed."""
    with _lock:
        job = _jobs.get(job_id)
        if job and job["user_id"] == user_id and job["status"] in ("done", "error"):
            del _jobs[job_id]
        elif not job:
            pass  # might only be in DB
        else:
            return False  # running/queued — can't dismiss
    try:
        db.delete_job(job_id, user_id)
    except Exception as exc:
        logger.warning("job dismiss DB delete failed: %s", exc)
    return True


def dismiss_all_errors(user_id: int) -> int:
    """Remove all error jobs for a user. Returns count removed."""
    removed = 0
    with _lock:
        to_del = [
            jid for jid, j in _jobs.items()
            if j["user_id"] == user_id and j["status"] == "error"
        ]
        for jid in to_del:
            del _jobs[jid]
            removed += 1
    try:
        db.delete_user_error_jobs(user_id)
    except Exception as exc:
        logger.warning("dismiss_all_errors DB failed: %s", exc)
    return removed


def run_in_background(job_id: str, fn, *args, **kwargs) -> None:
    """Launch fn(*args, **kwargs) in a daemon thread and track its lifecycle with semaphore gating."""

    def _worker():
        # Retain queued state until a concurrency slot becomes available
        update_job(job_id, status="queued", progress=0, message="Waiting in queue…")
        _scan_semaphore.acquire()
        try:
            update_job(job_id, status="running", progress=15, message="Scanning…")
            result = fn(*args, **kwargs)
            update_job(
                job_id,
                status="done",
                progress=100,
                message="Completed",
                result=result,
                report_token=result.get("report_token") if isinstance(result, dict) else None,
                completed_at=_now(),
            )
            logger.info("job done | job_id=%s", job_id)
        except Exception as exc:
            logger.exception("job failed | job_id=%s", job_id)
            update_job(
                job_id,
                status="error",
                progress=0,
                message=str(exc),
                error=str(exc),
                completed_at=_now(),
            )
        finally:
            _scan_semaphore.release()

    t = threading.Thread(target=_worker, daemon=True, name=f"scan-{job_id[:8]}")
    t.start()
