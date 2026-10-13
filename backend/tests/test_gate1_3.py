# -*- coding: utf-8 -*-
"""
test_gate1_3.py — Gate 1.3 Personal PhD Opportunity Tracker Verification Suite.
Refactored to standard pytest format with fixtures and assertions.
"""
import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
        if not get_user_by_username("gate13_user"):
            create_user("gate13_user", "Gate13Pass@2024!", role="analyst")
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
        yield c


def test_verify_primary_and_all_sources(client):
    r = client.get("/api/phd/stats")
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("ok") is True
    stats = data.get("stats", {})
    assert "total_opportunities" in stats
    assert "sources" in stats
    assert isinstance(stats["sources"], list)


def test_verify_opportunities_get_and_filtering(client):
    r = client.get("/api/phd/opportunities?limit=5")
    assert r.status_code == 200
    opps_data = r.get_json()
    assert "total" in opps_data
    assert "count" in opps_data
    assert isinstance(opps_data.get("opportunities"), list)

    r_filter = client.get("/api/phd/opportunities?status=applied")
    assert r_filter.status_code == 200
    applied_data = r_filter.get_json()
    assert "total" in applied_data

    r_search = client.get("/api/phd/opportunities?q=Inria")
    assert r_search.status_code == 200
    search_data = r_search.get_json()
    assert "total" in search_data


def test_verify_add_opportunity_post(client):
    new_opp = {
        "institution": "Oxford Cyber Security Lab",
        "country": "المملكة المتحدة",
        "program": "DPhil in Cyber Security",
        "field": "Cloud & Zero-Trust Architecture",
        "priority": "high",
        "status": "planned",
        "notes": "Gate 1.3 verification test opportunity",
    }
    r_post = client.post("/api/phd/opportunities", json=new_opp)
    assert r_post.status_code in (200, 201)
    post_data = r_post.get_json()
    assert post_data.get("ok") is True

    r_after = client.get("/api/phd/opportunities?q=Oxford")
    assert r_after.status_code == 200
    assert r_after.get_json()["total"] >= 1


def test_verify_profile_upcoming_applications_endpoints(client):
    endpoints = ["profile", "upcoming", "applications", "dashboard", "countries", "documents"]
    for ep in endpoints:
        resp = client.get(f"/api/phd/{ep}")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d.get("ok") is True


def test_verify_journey_and_intelligence_endpoints(client):
    rj = client.get("/api/journey")
    assert rj.status_code in (200, 404)
    ri = client.get("/api/intelligence/recent")
    assert ri.status_code in (200, 404)
