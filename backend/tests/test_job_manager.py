"""Tests for job_manager — in-memory + DB persistence."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db
import job_manager as jm


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test.db")
    monkeypatch.setenv("DB_PATH", db_file)
    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file
    db.init_db()
    # Clear in-memory job store
    jm._jobs.clear()
    yield
    jm._jobs.clear()
    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestCreateJob:
    def test_returns_uuid_string(self):
        job_id = jm.create_job("web", "example.com", 1, "alice")
        assert isinstance(job_id, str)
        assert len(job_id) == 36  # UUID format

    def test_job_queued_initially(self):
        job_id = jm.create_job("ssl", "test.com", 1, "alice")
        job = jm.get_job(job_id)
        assert job["status"] == "queued"
        assert job["progress"] == 0

    def test_job_persisted_to_db(self):
        job_id = jm.create_job("web", "example.com", 42, "bob")
        row = db.get_job_from_db(job_id)
        assert row is not None
        assert row["user_id"] == 42
        assert row["scan_type"] == "web"


class TestUpdateJob:
    def test_update_status(self):
        job_id = jm.create_job("web", "site.com", 1, "alice")
        jm.update_job(job_id, status="running", progress=50)
        job = jm.get_job(job_id)
        assert job["status"] == "running"
        assert job["progress"] == 50

    def test_update_persists_to_db(self):
        job_id = jm.create_job("web", "site.com", 1, "alice")
        jm.update_job(job_id, status="done", progress=100, message="OK")
        row = db.get_job_from_db(job_id)
        assert row["status"] == "done"

    def test_update_nonexistent_job_noop(self):
        jm.update_job("nonexistent-id", status="done")  # should not raise


class TestGetJob:
    def test_get_from_memory(self):
        job_id = jm.create_job("network", "192.168.1.1", 1, "alice")
        job = jm.get_job(job_id)
        assert job["target"] == "192.168.1.1"

    def test_get_falls_back_to_db(self):
        job_id = jm.create_job("web", "fallback.com", 5, "charlie")
        # Simulate restart: clear memory
        jm._jobs.clear()
        job = jm.get_job(job_id)
        assert job is not None
        assert job["target"] == "fallback.com"

    def test_unknown_job_returns_none(self):
        assert jm.get_job("00000000-0000-0000-0000-000000000000") is None


class TestGetUserJobs:
    def test_lists_only_user_jobs(self):
        jm.create_job("web", "a.com", 1, "alice")
        jm.create_job("ssl", "b.com", 2, "bob")
        alice_jobs = jm.get_user_jobs(1)
        assert all(j["user_id"] == 1 for j in alice_jobs)

    def test_merges_memory_and_db(self):
        jm.create_job("web", "mem.com", 7, "diana")
        jm.create_job("ssl", "db.com", 7, "diana")
        # Move one job to DB-only
        job_id = list(jm._jobs.keys())[0]
        del jm._jobs[job_id]
        jobs = jm.get_user_jobs(7)
        assert len(jobs) == 2


class TestRunInBackground:
    def test_successful_fn_sets_done(self):
        job_id = jm.create_job("web", "example.com", 1, "alice")

        def fake_scan():
            return {"report_token": "abc123"}

        jm.run_in_background(job_id, fake_scan)
        # Wait for thread
        for _ in range(20):
            if jm.get_job(job_id)["status"] == "done":
                break
            time.sleep(0.05)

        job = jm.get_job(job_id)
        assert job["status"] == "done"
        assert job["progress"] == 100
        assert job["report_token"] == "abc123"

    def test_failing_fn_sets_error(self):
        job_id = jm.create_job("web", "broken.com", 1, "alice")

        def broken_scan():
            raise ValueError("scan exploded")

        jm.run_in_background(job_id, broken_scan)
        for _ in range(20):
            if jm.get_job(job_id)["status"] == "error":
                break
            time.sleep(0.05)

        job = jm.get_job(job_id)
        assert job["status"] == "error"
        assert "exploded" in job["error"]
