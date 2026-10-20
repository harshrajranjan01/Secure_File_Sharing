
import time

import jwt
import pytest

from backend.auth.tokens import create_access_token


def test_create_access_token_returns_jwt_string(monkeypatch):
    """A valid user ID should produce a JWT string."""
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-for-unit-tests")

    token = create_access_token(1)

    assert isinstance(token, str)
    assert len(token) > 0


def test_decoded_token_contains_user_id(monkeypatch):
    """The sub claim should contain the user ID as a string."""
    secret = "test-secret-key-for-unit-tests"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)

    token = create_access_token(42)

    decoded = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
    )

    assert decoded["sub"] == "42"


def test_token_expires_after_approximately_15_minutes(monkeypatch):
    """The exp claim should be about 15 minutes after issuance."""
    secret = "test-secret-key-for-unit-tests"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)

    before_creation = int(time.time())

    token = create_access_token(42)

    after_creation = int(time.time())

    decoded = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
    )

    expected_expiration = 15 * 60

    assert before_creation + expected_expiration <= decoded["exp"]
    assert decoded["exp"] <= after_creation + expected_expiration


@pytest.mark.parametrize("user_id", [0, -1, -100])
def test_invalid_nonpositive_user_ids_raise_value_error(user_id):
    """Zero and negative IDs should be rejected."""
    with pytest.raises(ValueError):
        create_access_token(user_id)


@pytest.mark.parametrize("user_id", [True, False, "1", 1.5, None])
def test_invalid_user_id_types_raise_type_error(user_id):
    """Booleans and non-integer IDs should be rejected."""
    with pytest.raises(TypeError):
        create_access_token(user_id)


def test_missing_jwt_secret_raises_runtime_error(monkeypatch):
    """A missing secret should fail safely."""
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_access_token(1)


def test_blank_jwt_secret_raises_runtime_error(monkeypatch):
    """An empty or whitespace-only secret should be rejected."""
    monkeypatch.setenv("JWT_SECRET_KEY", "   ")

    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_access_token(1)
