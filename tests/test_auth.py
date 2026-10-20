
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app
from backend.database.user_repository import DuplicateUsernameError


client = TestClient(app)


@patch("backend.api.routes.auth.create_user")
@patch("backend.api.routes.auth.hash_password")
def test_register_user_success(mock_hash_password, mock_create_user):
    """A valid registration should return 201 and the new user's details."""

    mock_hash_password.return_value = "hashed_password_123"
    mock_create_user.return_value = 1

    response = client.post(
        "/auth/register",
        json={
            "username": "harsh123",
            "password": "SecurePass123",
        },
    )

    assert response.status_code == 201
    assert response.json() == {
        "id": 1,
        "username": "harsh123",
    }

    mock_hash_password.assert_called_once_with("SecurePass123")

    mock_create_user.assert_called_once_with(
        username="harsh123",
        password_hash="hashed_password_123",
    )


@patch("backend.api.routes.auth.create_user")
@patch("backend.api.routes.auth.hash_password")
def test_register_duplicate_username(
    mock_hash_password,
    mock_create_user,
):
    """Duplicate usernames should return HTTP 409."""

    mock_hash_password.return_value = "hashed_password_123"
    mock_create_user.side_effect = DuplicateUsernameError

    response = client.post(
        "/auth/register",
        json={
            "username": "harsh123",
            "password": "SecurePass123",
        },
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Username already exists."
    }


@patch("backend.api.routes.auth.create_user")
@patch("backend.api.routes.auth.hash_password")
def test_register_user_database_failure(
    mock_hash_password,
    mock_create_user,
):
    """A failed user creation should return HTTP 500."""

    mock_hash_password.return_value = "hashed_password_123"
    mock_create_user.return_value = None

    response = client.post(
        "/auth/register",
        json={
            "username": "harsh123",
            "password": "SecurePass123",
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Unable to register user."
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "username": "ab",
            "password": "SecurePass123",
        },
        {
            "username": "harsh123",
            "password": "short",
        },
    ],
)
def test_register_user_invalid_input(payload):
    """Invalid usernames and passwords should return HTTP 422."""

    response = client.post(
        "/auth/register",
        json=payload,
    )

    assert response.status_code == 422


def test_register_user_missing_fields():
    """Missing required fields should return HTTP 422."""

    response = client.post(
        "/auth/register",
        json={},
    )

    assert response.status_code == 422
