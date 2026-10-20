
import time

import jwt
import pytest

from backend.auth.tokens import create_access_token,verify_access_token


TEST_SECRET = "test-only-secret-key-for-jwt"

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




@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Use a temporary secret for every test."""
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)


def test_valid_token_returns_claims():
    token = create_access_token(123)

    claims = verify_access_token(token)

    assert claims is not None
    assert claims["sub"] == "123"
    assert "iat" in claims
    assert "exp" in claims


def test_empty_token_returns_none():
    assert verify_access_token("") is None
    assert verify_access_token("   ") is None


@pytest.mark.parametrize("token", [None, 123, True, [], {}])
def test_non_string_token_returns_none(token):
    assert verify_access_token(token) is None


def test_expired_token_returns_none():
    now = int(time.time())

    token = jwt.encode(
        {
            "sub": "123",
            "iat": now - 120,
            "exp": now - 60,
        },
        TEST_SECRET,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None


def test_wrong_secret_returns_none(monkeypatch):
    token = create_access_token(123)

    monkeypatch.setenv("JWT_SECRET_KEY", "different-test-secret")

    assert verify_access_token(token) is None


def test_modified_token_returns_none():
    token = create_access_token(123)
    parts = token.split(".")

    # Change the signature.
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    modified_token = ".".join(parts)

    assert verify_access_token(modified_token) is None


@pytest.mark.parametrize("missing_claim", ["sub", "iat", "exp"])
def test_missing_required_claim_returns_none(missing_claim):
    now = int(time.time())
    claims = {
        "sub": "123",
        "iat": now,
        "exp": now + 900,
    }
    del claims[missing_claim]

    token = jwt.encode(
        claims,
        TEST_SECRET,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None


@pytest.mark.parametrize(
    "subject",
    [
        "0",
        "-1",
        "admin",
        "001",
        "",
        "1.5",
    ],
)
def test_invalid_subject_returns_none(subject):
    now = int(time.time())

    token = jwt.encode(
        {
            "sub": subject,
            "iat": now,
            "exp": now + 900,
        },
        TEST_SECRET,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None


def test_non_string_subject_returns_none():
    now = int(time.time())

    token = jwt.encode(
        {
            "sub": 123,
            "iat": now,
            "exp": now + 900,
        },
        TEST_SECRET,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None


def test_missing_secret_returns_none(monkeypatch):
    token = create_access_token(123)

    monkeypatch.delenv("JWT_SECRET_KEY")

    assert verify_access_token(token) is None


def test_wrong_algorithm_returns_none():
    now = int(time.time())

    # The verifier must reject a token signed with HS384.
    token = jwt.encode(
        {
            "sub": "123",
            "iat": now,
            "exp": now + 900,
        },
        TEST_SECRET,
        algorithm="HS384",
    )

    assert verify_access_token(token) is None
