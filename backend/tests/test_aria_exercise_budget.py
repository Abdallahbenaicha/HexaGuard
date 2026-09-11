"""ARIA Exercise Call Budget and Ownership Test Suite (test_aria_exercise_budget.py).

Verifies:
- D-05: Atomic SQL budget enforcement (WHERE aria_calls_used < budget).
- D-06: Attempt ownership validation (cannot consume other user's budget).
- Calls tracked per attempt.
- 429 returned on budget exhaustion.
- General chat without exercise_attempt_id does not count against attempt budget.
"""

from concurrent.futures import ThreadPoolExecutor
import pytest
from database import (
    init_db,
    create_user,
    get_user_by_username,
    create_exercise,
    start_exercise_attempt,
    get_attempt,
    increment_attempt_aria_calls_atomic,
    _get_db,
)
from app import create_app


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_aria_budget.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-aria-budget-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("ARIA_EXERCISE_CALL_BUDGET", "5")
    init_db()


def test_aria_exercise_calls_tracked_per_attempt():
    """Each ARIA chat call with an exercise_attempt_id increments aria_calls_used."""
    create_user("learner_1", "Password123!", role="analyst", email="l1@test.local")
    user = get_user_by_username("learner_1")

    exercise = create_exercise("xss", "knowledge", "assessment", "XSS Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post(
        "/api/ai/chat",
        json={"message": "What is XSS?", "exercise_attempt_id": attempt["id"]},
    )
    assert resp.status_code == 200

    updated = get_attempt(attempt["id"])
    assert updated["aria_calls_used"] == 1


def test_aria_budget_enforced_at_limit(monkeypatch):
    """Calls up to the budget limit succeed."""
    monkeypatch.setenv("ARIA_EXERCISE_CALL_BUDGET", "3")
    create_user("learner_2", "Password123!", role="analyst", email="l2@test.local")
    user = get_user_by_username("learner_2")

    exercise = create_exercise("sqli", "knowledge", "assessment", "SQLi Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    for i in range(3):
        resp = client.post(
            "/api/ai/chat",
            json={"message": f"Question {i+1}", "exercise_attempt_id": attempt["id"]},
        )
        assert resp.status_code == 200

    updated = get_attempt(attempt["id"])
    assert updated["aria_calls_used"] == 3


def test_aria_budget_returns_429_when_exhausted(monkeypatch):
    """Calling ARIA past the budget limit returns 429 Too Many Requests."""
    monkeypatch.setenv("ARIA_EXERCISE_CALL_BUDGET", "2")
    create_user("learner_3", "Password123!", role="analyst", email="l3@test.local")
    user = get_user_by_username("learner_3")

    exercise = create_exercise("rce", "knowledge", "assessment", "RCE Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # First 2 calls succeed
    for _ in range(2):
        resp = client.post(
            "/api/ai/chat",
            json={"message": "Diagnostic help", "exercise_attempt_id": attempt["id"]},
        )
        assert resp.status_code == 200

    # 3rd call must be rejected with 429
    resp_exhausted = client.post(
        "/api/ai/chat",
        json={"message": "One more question", "exercise_attempt_id": attempt["id"]},
    )
    assert resp_exhausted.status_code == 429
    data = resp_exhausted.get_json()
    assert data["exercise_budget_exceeded"] is True
    assert data["used"] == 2


def test_aria_budget_race_condition_atomic_enforcement():
    """D-05: Concurrent requests cannot exceed the budget limit due to atomic SQL UPDATE."""
    create_user("learner_4", "Password123!", role="analyst", email="l4@test.local")
    user = get_user_by_username("learner_4")

    exercise = create_exercise("ssrf", "knowledge", "assessment", "SSRF Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])
    budget_limit = 4

    # Run 10 sequential / concurrent atomic increments targeting budget of 4
    results = []
    for _ in range(10):
        allowed, used = increment_attempt_aria_calls_atomic(attempt["id"], budget=budget_limit)
        results.append(allowed)

    # Exactly 4 should be allowed, and 6 rejected
    assert results.count(True) == 4
    assert results.count(False) == 6

    final_attempt = get_attempt(attempt["id"])
    assert final_attempt["aria_calls_used"] == 4


def test_aria_budget_simultaneous_threads_cannot_exceed_budget():
    """Prove two or more simultaneous concurrent threads cannot exceed the 5-call budget."""
    create_user("learner_concurrent", "Password123!", role="analyst", email="l_conc@test.local")
    user = get_user_by_username("learner_concurrent")

    exercise = create_exercise("xss", "knowledge", "assessment", "Concurrent Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])
    budget_limit = 5

    # Run 12 simultaneous worker threads trying to increment budget atomically
    def worker(_):
        allowed, used = increment_attempt_aria_calls_atomic(attempt["id"], budget=budget_limit)
        return allowed

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(12)))

    # Exactly 5 calls should succeed, and 7 calls must be blocked
    assert results.count(True) == 5
    assert results.count(False) == 7

    final_attempt = get_attempt(attempt["id"])
    assert final_attempt["aria_calls_used"] == 5


def test_aria_general_chat_not_counted_against_exercise_budget():
    """General ARIA chat without exercise_attempt_id does not count against attempt budget."""
    create_user("learner_5", "Password123!", role="analyst", email="l5@test.local")
    user = get_user_by_username("learner_5")

    exercise = create_exercise("xss", "knowledge", "assessment", "XSS Exercise")
    attempt = start_exercise_attempt(user["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    resp = client.post("/api/ai/chat", json={"message": "General cybersecurity question"})
    assert resp.status_code == 200

    attempt_after = get_attempt(attempt["id"])
    assert attempt_after["aria_calls_used"] == 0


def test_aria_budget_cannot_use_other_users_attempt():
    """D-06: User B cannot call ARIA with User A's exercise_attempt_id (HTTP 403)."""
    create_user("victim_learner", "Password123!", role="analyst", email="vl@test.local")
    create_user("attacker_learner", "Password123!", role="analyst", email="al@test.local")
    victim = get_user_by_username("victim_learner")
    attacker = get_user_by_username("attacker_learner")

    exercise = create_exercise("xss", "knowledge", "assessment", "Victim Exercise")
    victim_attempt = start_exercise_attempt(victim["id"], exercise["id"])

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(attacker["id"])
        sess["_fresh"] = True

    # Attacker tries to consume victim's attempt budget
    resp = client.post(
        "/api/ai/chat",
        json={"message": "Attacking victim budget", "exercise_attempt_id": victim_attempt["id"]},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert "Access denied" in data["error"]

    # Verify victim attempt's aria_calls_used is unchanged (0)
    updated = get_attempt(victim_attempt["id"])
    assert updated["aria_calls_used"] == 0
