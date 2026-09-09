"""F-01 Security & Reliability Tests: Background Scheduler Worker."""
import os
import sys
import time
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-f01-testing")

import database as db
import job_manager
import scheduler


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_f01.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("ENABLE_BACKGROUND_SCHEDULER", "false")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.init_db()
        db.create_user("sched_user", "TestPass123!", role="admin")
        yield flask_app

    scheduler.stop_scheduler()
    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestSchedulerExecution:
    def test_scheduler_dispatches_due_scans_and_updates_next_run(self, app):
        """F-01: Scheduler detects due scans (next_run_at <= now), runs them, and advances next_run_at."""
        now = datetime.now(timezone.utc)
        past_iso = (now - timedelta(minutes=10)).isoformat()
        future_iso = (now + timedelta(days=2)).isoformat()

        # Insert 1 due scan and 1 future scan
        due_id = db.create_scheduled_scan(
            user_id=1, username="sched_user", scan_type="web",
            target="due.example.com", cron_expr="daily"
        )
        db.update_scheduled_scan_run(due_id, last_run_at=None, next_run_at=past_iso)

        future_id = db.create_scheduled_scan(
            user_id=1, username="sched_user", scan_type="web",
            target="future.example.com", cron_expr="weekly"
        )
        db.update_scheduled_scan_run(future_id, last_run_at=None, next_run_at=future_iso)

        with patch("scanners.web_scanner.run_web_scan", return_value={"vulnerabilities": []}):
            dispatched = scheduler.run_scheduler_tick(app=app)

        assert len(dispatched) == 1, f"Expected 1 job dispatched, got {len(dispatched)}"
        job_id = dispatched[0]

        # Verify job is tracked in job_manager
        job = job_manager.get_job(job_id)
        assert job is not None
        assert job["target"] == "due.example.com"
        assert job["scan_type"] == "web"

        # Verify due scan next_run_at was updated to future
        scans = db.get_user_scheduled_scans(1)
        due_row = next(s for s in scans if s["id"] == due_id)
        assert due_row["next_run_at"] > now.isoformat()
        assert due_row["last_run_at"] is not None

        # Verify future scan was untouched
        future_row = next(s for s in scans if s["id"] == future_id)
        assert future_row["last_run_at"] is None

    def test_scheduler_respects_concurrency_cap(self, app):
        """F-01: Dispatched scheduled scans honor H-04 concurrency semaphore."""
        job_manager.set_concurrency_limit(1)

        now = datetime.now(timezone.utc)
        past_iso = (now - timedelta(minutes=5)).isoformat()

        id1 = db.create_scheduled_scan(1, "sched_user", "web", "t1.example.com", "daily")
        db.update_scheduled_scan_run(id1, None, past_iso)
        id2 = db.create_scheduled_scan(1, "sched_user", "web", "t2.example.com", "daily")
        db.update_scheduled_scan_run(id2, None, past_iso)

        block_event = threading.Event()
        start_event = threading.Event()

        def mock_slow_scan(target, **kwargs):
            start_event.set()
            block_event.wait(timeout=3)
            return {"vulnerabilities": []}

        with patch("scanners.web_scanner.run_web_scan", side_effect=mock_slow_scan):
            dispatched = scheduler.run_scheduler_tick(app=app)
            assert len(dispatched) == 2

            start_event.wait(timeout=2)
            time.sleep(0.3)

            stats = job_manager.get_active_jobs_stats()
            # Exactly 1 can be running since limit is 1
            assert stats["running"] <= 1
            assert stats["queued"] >= 1

            block_event.set()
            time.sleep(0.5)

        # Reset concurrency limit
        job_manager.set_concurrency_limit(3)

    def test_scheduler_thread_lifecycle(self, app):
        """F-01: Scheduler thread starts and stops gracefully."""
        assert not scheduler.is_scheduler_running()
        started = scheduler.start_scheduler(app=app, interval_seconds=1.0)
        assert started is True
        assert scheduler.is_scheduler_running()

        # Calling start again returns False (already running)
        assert scheduler.start_scheduler(app=app) is False

        scheduler.stop_scheduler()
        assert not scheduler.is_scheduler_running()
