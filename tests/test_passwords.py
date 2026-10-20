
import pytest

from backend.auth.passwords import hash_password, verify_password


def test_hash_valid_password():
    password_hash = hash_password("StrongPassword123!")

    assert isinstance(password_hash, str)
    assert password_hash.startswith("$argon2id$")
    assert password_hash != "StrongPassword123!"


def test_verify_correct_password():
    password_hash = hash_password("StrongPassword123!")

    assert verify_password("StrongPassword123!", password_hash) is True


def test_verify_wrong_password():
    password_hash = hash_password("StrongPassword123!")

    assert verify_password("WrongPassword123!", password_hash) is False


def test_hash_empty_password():
    with pytest.raises(ValueError):
        hash_password("")


def test_verify_malformed_hash():
    assert verify_password("StrongPassword123!", "malformed-hash") is False


@pytest.mark.parametrize(
    ("password", "password_hash"),
    [
        (None, "$argon2id$invalid"),
        (123, "$argon2id$invalid"),
        ("StrongPassword123!", None),
        ("StrongPassword123!", 123),
    ],
)
def test_verify_non_string_input(password, password_hash):
    assert verify_password(password, password_hash) is False


def test_verify_empty_password():
    password_hash = hash_password("StrongPassword123!")

    assert verify_password("", password_hash) is False


def test_verify_empty_hash():
    assert verify_password("StrongPassword123!", "") is False
