# -*- coding: utf-8 -*-
"""
Tests for Quota Reservation Lifecycle (fix/round3 Item 6).
Verifies:
1. reserve_quota, commit_quota, release_quota mechanics.
2. Failed scans release reserved quota (no deduction).
3. Successful scans commit quota.
4. Non-scanning paths like /fix_config do not consume or reserve quota.
"""
import pytest
from app import create_app
from database import (
    init_db,
    create_user,
    get_user_by_username,
    get_subscription,
    reserve_quota,
    commit_quota,
    release_quota,
)


@pytest.fixture
def app_with_quota_user(tmp_path, monkeypatch):
    test_db = str(tmp_path / "quota_test.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.app_context():
        init_db()
        create_user("quota_tester", "StrongPass@2024!", role="analyst")

    return app


def test_quota_direct_lifecycle_reserve_commit_release(app_with_quota_user):
    with app_with_quota_user.app_context():
        u = get_user_by_username("quota_tester")
        uid = u["id"]

        # Initial used is 0
        sub0 = get_subscription(uid)
        assert sub0["scans_used"] == 0

        # Reserve
        allowed, used, max_scans = reserve_quota(uid)
        assert allowed is True
        assert used == 1

        sub_res = get_subscription(uid)
        assert sub_res["scans_used"] == 1

        # Release (scan failed)
        new_used = release_quota(uid)
        assert new_used == 0

        sub_rel = get_subscription(uid)
        assert sub_rel["scans_used"] == 0

        # Reserve and commit (scan succeeded)
        allowed2, used2, _ = reserve_quota(uid)
        assert allowed2 is True
        assert used2 == 1
        commit_quota(uid)

        sub_com = get_subscription(uid)
        assert sub_com["scans_used"] == 1


def test_failed_scan_releases_reserved_quota(app_with_quota_user):
    client = app_with_quota_user.test_client()
    # Login
    login_res = client.post("/api/auth/login", json={
        "username": "quota_tester",
        "password": "StrongPass@2024!"
    })
    assert login_res.status_code == 200

    with app_with_quota_user.app_context():
        u = get_user_by_username("quota_tester")
        uid = u["id"]
        assert get_subscription(uid)["scans_used"] == 0

    # Launch scan with invalid target that will fail in validation (e.g. empty target or localhost forbidden)
    res = client.post("/scan_url", json={"url": "http://127.0.0.1:9999/test"})
    # Target lock or SSRF returns error status (400 or 403)
    assert res.status_code in (400, 403)

    # Verify quota was refunded / released
    with app_with_quota_user.app_context():
        sub = get_subscription(uid)
        assert sub["scans_used"] == 0, f"Expected 0 scans used after failed scan, got {sub['scans_used']}"


def test_fix_config_does_not_consume_quota(app_with_quota_user):
    client = app_with_quota_user.test_client()
    login_res = client.post("/api/auth/login", json={
        "username": "quota_tester",
        "password": "StrongPass@2024!"
    })
    assert login_res.status_code == 200

    with app_with_quota_user.app_context():
        u = get_user_by_username("quota_tester")
        uid = u["id"]
        assert get_subscription(uid)["scans_used"] == 0

    # POST to /fix_config with sample config
    res = client.post("/fix_config", data={
        "config_content": "ServerTokens OS\nServerSignature On"
    })
    # Should succeed or return html/json without consuming quota
    with app_with_quota_user.app_context():
        sub = get_subscription(uid)
        assert sub["scans_used"] == 0, "fix_config should not consume scan quota!"


def test_atomic_quota_reservation_under_concurrency(app_with_quota_user):
    """Under 10 concurrent reservation attempts for a user with 1 scan quota, exactly 1 succeeds."""
    import concurrent.futures

    with app_with_quota_user.app_context():
        u = get_user_by_username("quota_tester")
        uid = u["id"]

        def _try_reserve():
            with app_with_quota_user.app_context():
                allowed, used, max_s = reserve_quota(uid)
                return allowed

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_try_reserve) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        success_count = sum(1 for r in results if r is True)
        fail_count = sum(1 for r in results if r is False)

        assert success_count == 1, f"Expected exactly 1 reservation to succeed, got {success_count}"
        assert fail_count == 9, f"Expected 9 reservations to fail, got {fail_count}"

        sub = get_subscription(uid)
        assert sub["scans_used"] == 1


def test_async_scan_failure_releases_quota(app_with_quota_user):
    """When an asynchronous background scan worker fails with an exception, quota is refunded."""
    import time
    from job_manager import create_job, run_in_background, get_job

    with app_with_quota_user.app_context():
        u = get_user_by_username("quota_tester")
        uid = u["id"]

        # Reserve 1 slot
        allowed, used, max_s = reserve_quota(uid)
        assert allowed is True
        assert get_subscription(uid)["scans_used"] == 1

        # Launch an async job that will raise an error
        job_id = create_job("web", "http://failing.target.local", uid, "quota_tester")

        def _failing_worker():
            raise RuntimeError("Connection dropped by remote host")

        run_in_background(job_id, _failing_worker)

        # Wait briefly for thread to finish
        for _ in range(20):
            time.sleep(0.1)
            j = get_job(job_id)
            if j and j.get("status") == "error":
                break

        # Quota must be refunded back to 0
        sub_after = get_subscription(uid)
        assert sub_after["scans_used"] == 0, f"Expected scans_used refunded to 0, got {sub_after['scans_used']}"

