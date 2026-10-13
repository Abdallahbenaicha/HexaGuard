import os, pathlib, pytest
from app import create_app
from database import init_db, create_user, get_user_by_username
from blueprints.phd import _phd_dir

_PHD_DIR_EXISTS = _phd_dir().is_dir()


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
        if not get_user_by_username("phd_int_user"):
            create_user("phd_int_user", "PhdInt@2024!", role="analyst")
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
        yield c


@pytest.mark.skipif(not _PHD_DIR_EXISTS, reason="PhD data dir not present on this machine")
def test_opportunities_returns_records_from_xlsx(client):
    resp = client.get("/api/phd/opportunities?limit=500")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data["total"] >= 1


def test_opportunities_returns_data_dir_missing_when_absent(client, monkeypatch):
    monkeypatch.setenv("PHD_DATA_DIR", "/nonexistent_path_xyz")
    resp = client.get("/api/phd/opportunities")
    data = resp.get_json()
    assert data.get("error") == "data_dir_missing"
