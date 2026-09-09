"""Test suite for Part 3: Micro-Dojo Daily Challenges and Honest Streak Tracking.

Acceptance Criteria:
  1. Calling /api/dojo/today twice on the same day returns the exact same selection (deterministic).
  2. Calling on different days with simulated dates can yield different selections.
  3. Pending shadow backlog always takes precedence over random gap selection.
  4. Daily streak does NOT increase merely by opening the page without answering/completing.
  5. Answering correctly increments the daily streak.
"""

import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, store_report


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_dojo.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_dojo_selection_is_deterministic_per_day():
    """Calling /api/dojo/today repeatedly on the same day returns the exact same selection."""
    app = create_app()
    client = app.test_client()

    create_user("dojo_ninja", "Password123!", role="analyst", email="ninja@example.com")
    user = get_user_by_username("dojo_ninja")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Call 1
    r1 = client.get("/api/dojo/today?date=2026-09-09")
    assert r1.status_code == 200
    d1 = r1.get_json()
    vuln_1 = d1["vuln_type"]

    # Call 2 (same date)
    r2 = client.get("/api/dojo/today?date=2026-09-09")
    assert r2.status_code == 200
    d2 = r2.get_json()
    vuln_2 = d2["vuln_type"]

    # MUST be identical
    assert vuln_1 == vuln_2
    assert d1["question"]["id"] == d2["question"]["id"]


def test_dojo_selection_different_on_different_day():
    """Calling with simulated different dates can produce different selections."""
    app = create_app()
    client = app.test_client()

    create_user("dojo_scholar", "Password123!", role="analyst", email="scholar@example.com")
    user = get_user_by_username("dojo_scholar")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    selections = set()
    # Test across 10 simulated days
    for day in range(1, 11):
        date_str = f"2026-10-{day:02d}"
        res = client.get(f"/api/dojo/today?date={date_str}")
        assert res.status_code == 200
        selections.add(res.get_json()["vuln_type"])

    # Over 10 different days, user must get multiple distinct challenges
    assert len(selections) > 1, f"Expected varied challenges across days, got only: {selections}"


def test_shadow_backlog_takes_precedence():
    """A user with pending shadow tasks gets the oldest pending shadow task first."""
    app = create_app()
    client = app.test_client()

    create_user("dojo_cadet", "Password123!", role="analyst", email="cadet@example.com")
    user = get_user_by_username("dojo_cadet")
    user_id = user["id"]

    # Store a scan report with SSRF finding
    mock_scan = {
        "scan_type": "dast",
        "target": "https://dojo-target.internal",
        "vulnerabilities": [
            {"check": "ssrf_test", "title": "Server side request forgery detected", "severity": "high"}
        ],
    }
    store_report(mock_scan, risk_score=8.0, original_content=None, user_id=user_id, username="dojo_cadet")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    res = client.get("/api/dojo/today")
    assert res.status_code == 200
    data = res.get_json()
    assert data["source"] == "shadow_backlog"
    assert data["vuln_type"] == "ssrf"


def test_streak_does_not_increment_by_opening_page():
    """Streak does NOT increase simply by GET requests to /api/dojo/today without answering."""
    app = create_app()
    client = app.test_client()

    create_user("dojo_lurker", "Password123!", role="analyst", email="lurker@example.com")
    user = get_user_by_username("dojo_lurker")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # 1. First visit
    r1 = client.get("/api/dojo/today?date=2026-09-09")
    assert r1.get_json()["streak_days"] == 0
    assert r1.get_json()["today_completed"] is False

    # 2. Revisit 5 times on same day
    for _ in range(5):
        r_repeat = client.get("/api/dojo/today?date=2026-09-09")
        assert r_repeat.get_json()["streak_days"] == 0

    # 3. Visit next day without answering
    r2 = client.get("/api/dojo/today?date=2026-09-10")
    assert r2.get_json()["streak_days"] == 0


def test_streak_increments_only_on_correct_completion():
    """Streak increments by 1 when answer is correct, and consecutive days build up the streak."""
    app = create_app()
    client = app.test_client()

    create_user("dojo_champion", "Password123!", role="analyst", email="champion@example.com")
    user = get_user_by_username("dojo_champion")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    # Day 1: 2026-09-08
    d1 = client.get("/api/dojo/today?date=2026-09-08").get_json()
    vt1 = d1["vuln_type"]

    # Submit wrong answer first
    wrong_res = client.post(
        "/api/dojo/answer",
        json={"vuln_type": vt1, "choice_index": 99, "date": "2026-09-08"},
    )
    assert wrong_res.get_json()["correct"] is False

    # Still 0 streak
    assert client.get("/api/dojo/today?date=2026-09-08").get_json()["streak_days"] == 0

    # Submit correct answer for Day 1
    # For default questions: xss is 1, sqli is 1, default is 0
    from blueprints.dojo import QUESTION_BANK
    q_data = QUESTION_BANK.get(vt1, QUESTION_BANK["default"])
    correct_idx = q_data["correct_index"]

    good_res = client.post(
        "/api/dojo/answer",
        json={"vuln_type": vt1, "choice_index": correct_idx, "date": "2026-09-08"},
    )
    assert good_res.get_json()["correct"] is True
    assert good_res.get_json()["streak_days"] == 1

    # Day 2: 2026-09-09 (consecutive day)
    d2 = client.get("/api/dojo/today?date=2026-09-09").get_json()
    # Before answering day 2, streak is active from yesterday (1 day)
    assert d2["streak_days"] == 1
    vt2 = d2["vuln_type"]
    q_data2 = QUESTION_BANK.get(vt2, QUESTION_BANK["default"])

    good_res2 = client.post(
        "/api/dojo/answer",
        json={"vuln_type": vt2, "choice_index": q_data2["correct_index"], "date": "2026-09-09"},
    )
    assert good_res2.get_json()["correct"] is True
    assert good_res2.get_json()["streak_days"] == 2
