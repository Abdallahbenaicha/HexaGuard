"""Test suite for E-01: Learning Tracks Blueprint.

Verifies:
  1. Unauthorized access to /api/tracks is denied.
  2. Authenticated user can list all tracks with computed progress.
  3. Detail route /api/tracks/<id> returns per-step breakdown.
  4. Non-existent track ID returns 404.
  5. Progress calculation accounts for practiced skills and dojo streak bonuses.
"""

import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username
from blueprints.tracks import _TRACKS, _compute_track_progress


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_tracks.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-123")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_tracks_unauthorized():
    """Anonymous client GET /api/tracks must be rejected (401 or redirect to login)."""
    app = create_app()
    client = app.test_client()
    res = client.get("/api/tracks")
    assert res.status_code in (401, 302)


def test_tracks_list():
    """Authenticated user receives all defined tracks with progress dictionary."""
    app = create_app()
    client = app.test_client()

    create_user("track_explorer", "Password123!", role="analyst", email="explorer@example.com")
    user = get_user_by_username("track_explorer")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/tracks")
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    tracks = data.get("tracks", [])
    assert len(tracks) == len(_TRACKS)

    track_ids = {t["id"] for t in tracks}
    assert "bug-bounty-hunter" in track_ids
    assert "soc-analyst" in track_ids
    assert "ejpt-oscp-readiness" in track_ids

    for t in tracks:
        assert "progress" in t
        assert "percent" in t["progress"]
        assert 0 <= t["progress"]["percent"] <= 100


def test_track_detail_success():
    """Valid track ID returns track details and steps breakdown."""
    app = create_app()
    client = app.test_client()

    create_user("track_detailer", "Password123!", role="analyst", email="detailer@example.com")
    user = get_user_by_username("track_detailer")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/tracks/bug-bounty-hunter")
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    assert "track" in data
    assert "steps" in data
    assert len(data["steps"]) > 0
    assert any(s["vuln_type"] == "sqli" for s in data["steps"])


def test_track_detail_not_found():
    """Non-existent track returns 404."""
    app = create_app()
    client = app.test_client()

    create_user("track_ghost", "Password123!", role="analyst", email="ghost@example.com")
    user = get_user_by_username("track_ghost")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/tracks/unknown-phantom-track")
    assert res.status_code == 404
    data = res.get_json()
    assert data.get("ok") is False


def test_progress_calculation_logic():
    """Unit test progress calculation algorithm directly."""
    track = {
        "id": "test-track",
        "required_vuln_types": ["xss", "sqli", "csrf", "rce"],
        "shadow_weight": 0.10,
        "dojo_streak_bonus_threshold": 5,
        "dojo_streak_bonus_pct": 0.10,
    }
    # Case 1: Empty ledger
    res_empty = _compute_track_progress(track, [], user_id=999999)
    assert res_empty["percent"] >= 0
    assert len(res_empty["practiced"]) == 0
    assert set(res_empty["missing"]) == {"xss", "sqli", "csrf", "rce"}

    # Case 2: 2 of 4 practiced
    mock_ledger = [
        {"vuln_type": "xss", "practiced_count": 2},
        {"vuln_type": "sqli", "practiced_count": 1},
    ]
    res_partial = _compute_track_progress(track, mock_ledger, user_id=999999)
    assert "xss" in res_partial["practiced"]
    assert "sqli" in res_partial["practiced"]
    assert "csrf" in res_partial["missing"]
    assert res_partial["percent"] > 0


def test_cert_readiness_endpoint():
    """Authenticated user receives external certification readiness calculations (E-04)."""
    app = create_app()
    client = app.test_client()

    create_user("cert_aspirant", "Password123!", role="analyst", email="aspirant@example.com")
    user = get_user_by_username("cert_aspirant")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(user["id"])
        sess["_fresh"] = True

    res = client.get("/api/tracks/cert-readiness")
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("ok") is True
    certs = data.get("certifications", [])
    assert len(certs) == 3

    cert_ids = {c["id"] for c in certs}
    assert "ejpt" in cert_ids
    assert "oscp" in cert_ids
    assert "secplus" in cert_ids

    for c in certs:
        assert "readiness_pct" in c
        assert "disclaimer_en" in c
        assert "covered_skills" in c
        assert "missing_skills" in c
