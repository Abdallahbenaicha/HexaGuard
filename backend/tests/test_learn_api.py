"""Tests for SecuraX Education & Learning API Blueprint (Phase 1 & Phase 2)."""

import pytest
from app import create_app
from database import init_db


@pytest.fixture(autouse=True)
def setup_test_app(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_learn.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-learn")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()


def test_get_taxonomy_success():
    """Verify GET /api/learn/taxonomy returns all offensive engines and Blue Team incidents."""
    app = create_app()
    client = app.test_client()

    res = client.get("/api/learn/taxonomy")
    assert res.status_code == 200
    data = res.get_json()

    assert data.get("ok") is True
    assert "vulns" in data
    assert "incidents" in data
    assert "scanners" in data
    assert len(data["scanners"]) == 11
    assert "xss" in data["vulns"]
    assert "sqli" in data["vulns"]
    assert "phishing" in data["incidents"]


def test_get_single_topic_offensive():
    """Verify GET /api/learn/taxonomy/<id> returns offensive finding details."""
    app = create_app()
    client = app.test_client()

    res = client.get("/api/learn/taxonomy/xss")
    assert res.status_code == 200
    data = res.get_json()

    assert data.get("ok") is True
    assert data.get("topic_type") == "offensive"
    topic = data.get("topic", {})
    assert topic.get("id") == "xss"
    assert "Cross-Site Scripting" in topic.get("name_en", "")


def test_get_single_topic_incident():
    """Verify GET /api/learn/taxonomy/<id> returns Blue Team incident details."""
    app = create_app()
    client = app.test_client()

    res = client.get("/api/learn/taxonomy/phishing")
    assert res.status_code == 200
    data = res.get_json()

    assert data.get("ok") is True
    assert data.get("topic_type") == "incident"
    topic = data.get("topic", {})
    assert topic.get("id") == "phishing"
    assert "Phishing" in topic.get("name_en", "")


def test_get_single_topic_not_found():
    """Verify GET /api/learn/taxonomy/<non_existent> returns 404."""
    app = create_app()
    client = app.test_client()

    res = client.get("/api/learn/taxonomy/non_existent_topic_xyz")
    assert res.status_code == 404
    data = res.get_json()
    assert data.get("ok") is False


def test_get_methodology():
    """Verify GET /api/learn/methodology returns Module 0 assessment phases and decision matrix."""
    app = create_app()
    client = app.test_client()

    res = client.get("/api/learn/methodology")
    assert res.status_code == 200
    data = res.get_json()

    assert data.get("ok") is True
    methodology = data.get("methodology", {})
    assert len(methodology.get("phases", [])) == 7
    phase_numbers = [p["number"] for p in methodology["phases"]]
    assert phase_numbers == [1, 2, 3, 4, 5, 6, 7]
    assert len(methodology.get("decision_matrix", [])) >= 10
