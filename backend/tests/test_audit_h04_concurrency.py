"""H-04 Security Tests: Concurrency cap and aggregate rate limit."""
import os
import sys
import time
import threading
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-h04-testing")

import job_manager
import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_h04.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AGGREGATE_SCAN_LIMIT_PER_MINUTE", "5")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    from blueprints.scans import reset_aggregate_scan_history
    reset_aggregate_scan_history()
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
    )
    with flask_app.app_context():
        db.init_db()
        db.create_user("concurrency_analyst", "TestPass123!", role="admin")
        yield flask_app

    reset_aggregate_scan_history()

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestJobManagerConcurrencyCap:
    def test_running_jobs_do_not_exceed_concurrency_cap(self):
        """H-04 (A): When N > cap jobs are submitted, running jobs NEVER exceed MAX_CONCURRENT_SCANS."""
        job_manager.set_concurrency_limit(2)

        start_event = threading.Event()
        release_event = threading.Event()

        def slow_task():
            start_event.set()
            release_event.wait(timeout=5)
            return {"status": "ok"}

        # Launch 5 jobs
        job_ids = []
        for i in range(5):
            jid = job_manager.create_job("web", f"target-{i}.example.com", 1, "test_user")
            job_ids.append(jid)
            job_manager.run_in_background(jid, slow_task)

        # Wait until tasks start
        start_event.wait(timeout=2)
        time.sleep(0.2)  # Allow worker threads to attempt acquire

        # Check job statuses
        stats = job_manager.get_active_jobs_stats()
        assert stats["running"] <= 2, f"Expected <= 2 running, got {stats['running']}"
        assert stats["queued"] >= 3, f"Expected >= 3 queued, got {stats['queued']}"

        # Release first batch
        release_event.set()
        time.sleep(0.5)

        # Reset limit to default
        job_manager.set_concurrency_limit(3)


class TestAggregateRateLimit:
    def test_aggregate_rate_limit_across_endpoints(self, app):
        """H-04 (B): Aggregated scan requests across different routes are rate-limited per user."""
        client = app.test_client()
        client.post(
            "/api/auth/login",
            json={"username": "concurrency_analyst", "password": "TestPass123!"},
        )

        with patch("blueprints.scans.run_web_scan", return_value={"vulnerabilities": []}), \
             patch("blueprints.scans.run_ssl_scan", return_value={"vulnerabilities": []}):
            # Send 5 requests across different endpoints (limit set to 5 in fixture)
            for i in range(5):
                endpoint = "/scan_url" if i % 2 == 0 else "/scan_ssl"
                payload = {"url": "https://example.com"} if endpoint == "/scan_url" else {"target": "example.com"}
                res = client.post(endpoint, json=payload)
                assert res.status_code == 200, f"Request {i} failed with {res.status_code}"

            # 6th request must be rejected with 429 Too Many Requests
            res6 = client.post("/scan_url", json={"url": "https://example.com"})
            assert res6.status_code == 429
            data = res6.get_json() or {}
            assert data.get("rate_limited") is True or "rate limit" in data.get("error", "").lower()
