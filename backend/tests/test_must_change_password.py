import pytest
from app import create_app
from database import init_db, create_user, get_user_by_username, update_user


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
        if not get_user_by_username("pw_test_user"):
            create_user("pw_test_user", "TestPass@2024!", role="analyst")
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_normal_user_no_password_change_required(client):
    # Login normal user
    res = client.post("/api/auth/login", json={
        "username": "pw_test_user",
        "password": "TestPass@2024!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data.get("must_change_password") is False

    # Check that protected endpoint is accessible
    res_me = client.get("/api/auth/me")
    assert res_me.status_code == 200
    assert res_me.get_json()["authenticated"] is True


def test_flagged_user_blocked_until_password_changed(app, client):
    with app.app_context():
        u = get_user_by_username("pw_test_user")
        update_user(u["id"], must_change_password=1)

    # Login flagged user
    res = client.post("/api/auth/login", json={
        "username": "pw_test_user",
        "password": "TestPass@2024!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["must_change_password"] is True

    # Other API endpoints should be blocked with 403
    res_blocked = client.get("/api/auth/token")
    assert res_blocked.status_code == 403
    assert res_blocked.get_json()["must_change_password"] is True

    # /api/auth/change-password must be allowed
    res_change = client.post("/api/auth/change-password", json={
        "current_password": "TestPass@2024!",
        "new_password": "NewSecretPass@2025!"
    })
    assert res_change.status_code == 200
    assert res_change.get_json()["ok"] is True

    # After relogin with new password, must_change_password is False and access restored
    res_new_login = client.post("/api/auth/login", json={
        "username": "pw_test_user",
        "password": "NewSecretPass@2025!"
    })
    assert res_new_login.status_code == 200
    assert res_new_login.get_json()["must_change_password"] is False

    res_restored = client.get("/api/auth/token")
    assert res_restored.status_code == 200
