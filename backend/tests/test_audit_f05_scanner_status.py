"""F-05 Tests: Scanner tools status endpoint and tool readiness detection."""
import os
import sys
from unittest.mock import patch
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-f05-testing")

import database as db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_f05.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.init_db()
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestScannerStatusEndpoint:
    def test_scanners_status_structure(self, app):
        """F-05: GET /api/scanners/status reports tool availability and missing list."""
        client = app.test_client()
        res = client.get("/api/scanners/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("ok") is True
        tools = data.get("tools", {})
        for required_tool in ("nuclei", "zap", "nikto", "nmap", "trivy", "sslyze"):
            assert required_tool in tools
            assert "available" in tools[required_tool]
            assert "category" in tools[required_tool]
            assert "install_hint" in tools[required_tool]

        assert "dast_ready" in data
        assert "dast_missing" in data
        assert isinstance(data["dast_missing"], list)

    def test_nuclei_cloud_api_detection(self, app, monkeypatch):
        """F-05: Setting PDCP_API_KEY marks nuclei as available via cloud_api."""
        monkeypatch.setenv("PDCP_API_KEY", "test-cloud-api-key")
        with patch("shutil.which", return_value=None):
            client = app.test_client()
            res = client.get("/api/scanners/status")
            assert res.status_code == 200
            data = res.get_json()
            nuclei = data["tools"]["nuclei"]
            assert nuclei["available"] is True
            assert nuclei["provider"] == "cloud_api"
