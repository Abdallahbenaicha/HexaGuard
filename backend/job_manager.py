"""HexaGuard — background scan job manager with SQLite persistence.

Jobs are written to the scan_jobs table on every state change, so they
survive server restarts.  An in-memory mirror is kept for fast reads.
"""

import logging
import threading
import uuid
from datetime import datetime, timezone, timedelta

import database as db

logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_TTL_MINUTES = 60


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


def run_in_background(job_id: str, fn, *args, **kwargs) -> None:
    """Launch fn(*args, **kwargs) in a daemon thread and track its lifecycle."""

    def _worker():
        update_job(job_id, status="running", progress=15, message="Scanning…")
        try:
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

    t = threading.Thread(target=_worker, daemon=True, name=f"scan-{job_id[:8]}")
    t.start()
