"""
test_bounty_partial_failure.py
P0-B regression test: one platform failing must NOT crash the endpoint.
Evidence: federacy_data.json was 404, caused HTTP 500. Fix: per-platform try/except.
"""
import pytest
import requests as _requests
from unittest.mock import patch, MagicMock
from app import create_app
from database import init_db, create_user, get_user_by_username


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
        if not get_user_by_username("bounty_test_user"):
            create_user("bounty_test_user", "BountyTest@2024!", role="analyst")
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
        yield c


def _make_requests_get_mock(fail_url_fragment="hackerone"):
    """
    Returns a mock for requests.get that raises HTTPError for one platform URL
    and returns an empty valid JSON list for others.
    This tests the per-platform try/except in api_bounty_targets_by_skill.
    """
    def _mock_get(url, **kwargs):
        if fail_url_fragment in url:
            resp = MagicMock()
            resp.raise_for_status.side_effect = _requests.exceptions.HTTPError(
                f"404 Client Error: Not Found for url: {url}"
            )
            return resp
        # Other platforms: return empty JSON list (valid, no crash)
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.iter_content.return_value = [b"[]"]
        return resp
    return _mock_get


def test_endpoint_returns_200_when_one_platform_fails(client):
    """
    P0-B: Even if one platform's fetch raises, the endpoint must return HTTP 200
    (not 500) with partial results from the other platforms.
    Evidence fix: per-platform try/except in api_bounty_targets_by_skill.
    Mocks requests.get at the HTTP level so _fetch_platform.raise_for_status() fires.
    """
    # Clear cache so mock is actually called
    from blueprints.bounty import _BB_CACHE
    _BB_CACHE.clear()

    with patch("blueprints.bounty.requests.get", side_effect=_make_requests_get_mock("hackerone")):
        resp = client.get("/api/bounty/targets-by-skill/xss")

    assert resp.status_code == 200, (
        f"Expected HTTP 200 with partial results, got {resp.status_code}. "
        "Per-platform isolation failed."
    )
    data = resp.get_json()
    assert "platform_errors" in data, "Response must include platform_errors field"
    assert "hackerone" in data["platform_errors"], (
        f"Failed platform must appear in platform_errors. Got: {data['platform_errors']}"
    )
    assert isinstance(data.get("targets"), list), "targets field must be a list"


def test_endpoint_returns_200_when_all_platforms_ok(client):
    """All platforms return empty JSON list (no network) — must get 200 with empty platform_errors."""
    from blueprints.bounty import _BB_CACHE
    _BB_CACHE.clear()

    # Each platform returns b'[]' — valid empty JSON
    ok_resp = MagicMock()
    ok_resp.raise_for_status.return_value = None
    ok_resp.iter_content.return_value = [b"[]"]

    with patch("blueprints.bounty.requests.get", return_value=ok_resp):
        resp = client.get("/api/bounty/targets-by-skill/sqli")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("platform_errors") == {}, f"No errors expected when all OK. Got: {data.get('platform_errors')}"
    assert isinstance(data.get("targets"), list)


def test_federacy_not_in_normalisers():
    """
    federacy must NOT be in _NORMALISERS after removal.
    Evidence: federacy_data.json returns HTTP 404.
    """
    from blueprints.bounty import _NORMALISERS, _PLATFORM_URLS
    assert "federacy" not in _NORMALISERS, (
        "federacy must be removed from _NORMALISERS (404 source)"
    )
    assert "federacy" not in _PLATFORM_URLS, (
        "federacy must be removed from _PLATFORM_URLS (404 source)"
    )
