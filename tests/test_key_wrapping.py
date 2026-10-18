import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from backend.crypto.key_wrapping import unwrap_file_key, wrap_file_key


@pytest.fixture
def test_kek(monkeypatch):
    """Configure a fresh, temporary 256-bit KEK for each test."""

    kek = os.urandom(32)
    kek_base64 = base64.b64encode(kek).decode("ascii")

    monkeypatch.setenv("KEK_BASE64", kek_base64)

    return kek


def test_valid_dek_produces_correct_lengths(test_kek):
    """Verify wrapping returns the expected AES-GCM ciphertext and nonce sizes."""

    dek = os.urandom(32)

    result = wrap_file_key(dek)

    assert len(result["wrapped_dek"]) == 48
    assert len(result["nonce"]) == 12


def test_wrapped_dek_round_trips(test_kek):
    """Verify a wrapped DEK decrypts back to its original value."""

    dek = os.urandom(32)

    encrypted_package = wrap_file_key(dek)

    assert unwrap_file_key(encrypted_package) == dek


def test_wrapping_same_dek_produces_different_nonces(test_kek):
    """Verify every encryption uses a fresh random AES-GCM nonce."""

    dek = os.urandom(32)

    first = wrap_file_key(dek)
    second = wrap_file_key(dek)

    assert first["nonce"] != second["nonce"]
    assert first["wrapped_dek"] != second["wrapped_dek"]


def test_string_dek_raises_type_error(test_kek):
    """Reject DEKs that are not byte strings."""

    with pytest.raises(TypeError, match="DEK must be bytes"):
        wrap_file_key("this is not bytes")


def test_wrong_length_dek_raises_value_error(test_kek):
    """Reject DEKs that are not 32 bytes long."""

    with pytest.raises(ValueError, match="DEK must be exactly 32 bytes"):
        wrap_file_key(os.urandom(16))


def test_missing_kek_raises_value_error(monkeypatch):
    """Reject encryption when the KEK environment variable is missing."""

    monkeypatch.delenv("KEK_BASE64", raising=False)

    with pytest.raises(ValueError, match="not configured"):
        wrap_file_key(os.urandom(32))


def test_invalid_base64_kek_raises_value_error(monkeypatch):
    """Reject a KEK environment value that is not valid Base64."""

    monkeypatch.setenv("KEK_BASE64", "not-valid-base64!")

    with pytest.raises(ValueError, match="not valid Base64"):
        wrap_file_key(os.urandom(32))


def test_wrong_length_kek_raises_value_error(monkeypatch):
    """Reject a decoded KEK that is not 32 bytes long."""

    short_kek = os.urandom(16)
    encoded_kek = base64.b64encode(short_kek).decode("ascii")

    monkeypatch.setenv("KEK_BASE64", encoded_kek)

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        wrap_file_key(os.urandom(32))


@pytest.mark.parametrize("package", [None, [], "not a dictionary"])
def test_invalid_package_type_raises_type_error(test_kek, package):
    """Reject encrypted packages that are not dictionaries."""

    with pytest.raises(TypeError, match="dictionary"):
        unwrap_file_key(package)


@pytest.mark.parametrize(
    "package",
    [
        {},
        {"wrapped_dek": b"ciphertext"},
        {"nonce": b"nonce"},
    ],
)
def test_missing_package_fields_raise_value_error(test_kek, package):
    """Reject packages missing the ciphertext or nonce fields."""

    with pytest.raises(ValueError, match="must contain"):
        unwrap_file_key(package)


def test_non_bytes_wrapped_dek_raises_type_error(test_kek):
    """Reject ciphertext values that are not bytes."""

    package = {
        "wrapped_dek": "not bytes",
        "nonce": os.urandom(12),
    }

    with pytest.raises(TypeError, match="Wrapped DEK must be bytes"):
        unwrap_file_key(package)


def test_non_bytes_nonce_raises_type_error(test_kek):
    """Reject nonce values that are not bytes."""

    package = {
        "wrapped_dek": os.urandom(48),
        "nonce": "not bytes",
    }

    with pytest.raises(TypeError, match="Nonce must be bytes"):
        unwrap_file_key(package)


def test_wrong_length_wrapped_dek_raises_value_error(test_kek):
    """Reject wrapped DEKs with an invalid AES-GCM output length."""

    package = {
        "wrapped_dek": os.urandom(47),
        "nonce": os.urandom(12),
    }

    with pytest.raises(ValueError, match="Wrapped DEK must be exactly 48 bytes"):
        unwrap_file_key(package)


def test_wrong_length_nonce_raises_value_error(test_kek):
    """Reject nonces that are not 12 bytes long."""

    package = {
        "wrapped_dek": os.urandom(48),
        "nonce": os.urandom(11),
    }

    with pytest.raises(ValueError, match="Nonce must be exactly 12 bytes"):
        unwrap_file_key(package)


def test_tampered_ciphertext_raises_invalid_tag(test_kek):
    """Verify AES-GCM rejects modified ciphertext."""

    encrypted_package = wrap_file_key(os.urandom(32))
    tampered_package = dict(encrypted_package)

    ciphertext = encrypted_package["wrapped_dek"]
    tampered_package["wrapped_dek"] = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(InvalidTag):
        unwrap_file_key(tampered_package)


def test_tampered_nonce_raises_invalid_tag(test_kek):
    """Verify AES-GCM rejects a modified nonce."""

    encrypted_package = wrap_file_key(os.urandom(32))
    tampered_package = dict(encrypted_package)

    nonce = encrypted_package["nonce"]
    tampered_package["nonce"] = nonce[:-1] + bytes([nonce[-1] ^ 1])

    with pytest.raises(InvalidTag):
        unwrap_file_key(tampered_package)