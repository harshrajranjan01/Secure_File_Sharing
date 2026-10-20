from fastapi.testclient import TestClient

from main import app
from backend.api.routes import auth


client = TestClient(app)


def test_login_success(monkeypatch):
    """Valid credentials should return an access token."""

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {
            "id": 1,
            "username": username,
            "password_hash": "stored_hash",
        },
    )

    monkeypatch.setattr(
        auth,
        "verify_password",
        lambda password, password_hash: True,
    )

    monkeypatch.setattr(
        auth,
        "create_access_token",
        lambda user_id: "test.jwt.token",
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "testuser",
            "password": "StrongPassword123",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "test.jwt.token",
        "token_type": "bearer",
    }


def test_login_unknown_username(monkeypatch):
    """Unknown username should return 401."""

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: None,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "unknownuser",
            "password": "StrongPassword123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_login_wrong_password(monkeypatch):
    """Incorrect password should return 401."""

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {
            "id": 1,
            "username": username,
            "password_hash": "stored_hash",
        },
    )

    monkeypatch.setattr(
        auth,
        "verify_password",
        lambda password, password_hash: False,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "testuser",
            "password": "WrongPassword123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_login_failures_use_same_error(monkeypatch):
    """Unknown usernames and wrong passwords should return the same error."""

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: None,
    )

    unknown_user_response = client.post(
        "/auth/login",
        json={
            "username": "unknownuser",
            "password": "StrongPassword123",
        },
    )

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {
            "id": 1,
            "username": username,
            "password_hash": "stored_hash",
        },
    )

    monkeypatch.setattr(
        auth,
        "verify_password",
        lambda password, password_hash: False,
    )

    wrong_password_response = client.post(
        "/auth/login",
        json={
            "username": "testuser",
            "password": "WrongPassword123",
        },
    )

    assert unknown_user_response.status_code == 401
    assert wrong_password_response.status_code == 401

    assert (
        unknown_user_response.json()["detail"]
        == wrong_password_response.json()["detail"]
        == "Invalid username or password."
    )


def test_login_does_not_return_password_hash(monkeypatch):
    """The response must not expose the stored password hash."""

    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {
            "id": 1,
            "username": username,
            "password_hash": "secret_stored_hash",
        },
    )

    monkeypatch.setattr(
        auth,
        "verify_password",
        lambda password, password_hash: True,
    )

    monkeypatch.setattr(
        auth,
        "create_access_token",
        lambda user_id: "test.jwt.token",
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "testuser",
            "password": "StrongPassword123",
        },
    )

    assert response.status_code == 200
    assert "password_hash" not in response.json()
    assert "secret_stored_hash" not in response.text