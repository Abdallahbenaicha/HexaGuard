"""SecurAx — in-process background scan job manager.

Uses daemon threads (no Celery / Redis needed on PythonAnywhere).
Jobs live in memory and are cleaned up after 30 minutes.
"""

import logging
import threading
import uuid
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()

_TTL_MINUTES = 30


def _purge_old():
    """Remove completed/errored jobs older than TTL."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=_TTL_MINUTES)
    to_del = [
        jid for jid, j in _jobs.items()
        if j["status"] in ("done", "error")
        and j.get("completed_at")
        and datetime.fromisoformat(j["completed_at"]) < cutoff
    ]
    for jid in to_del:
        del _jobs[jid]


def create_job(scan_type: str, target: str, user_id: int, username: str) -> str:
    job_id = str(uuid.uuid4())
    with _lock:
        _purge_old()
        _jobs[job_id] = {
            "job_id":       job_id,
            "scan_type":    scan_type,
            "target":       target,
            "user_id":      user_id,
            "username":     username,
            "status":       "queued",   # queued | running | done | error
            "progress":     0,
            "message":      "Queued…",
            "result":       None,
            "error":        None,
            "report_token": None,
            "started_at":   datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
        }
    return job_id


def update_job(job_id: str, **kwargs) -> None:
    with _lock:
        if job_id in _jobs:
            _jobs[job_id].update(kwargs)


def get_job(job_id: str) -> dict | None:
    with _lock:
        j = _jobs.get(job_id)
        return dict(j) if j else None


def get_user_jobs(user_id: int) -> list[dict]:
    with _lock:
        return [dict(j) for j in _jobs.values() if j["user_id"] == user_id]


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
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            logger.info("job done | job_id=%s type=%s", job_id, _jobs.get(job_id, {}).get("scan_type"))
        except Exception as exc:
            logger.exception("job failed | job_id=%s", job_id)
            update_job(
                job_id,
                status="error",
                progress=0,
                message=str(exc),
                error=str(exc),
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

    t = threading.Thread(target=_worker, daemon=True, name=f"scan-{job_id[:8]}")
    t.start()
