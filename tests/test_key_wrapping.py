
import base64
import os

import pytest

from backend.crypto.key_wrapping import wrap_file_key


@pytest.fixture
def test_kek(monkeypatch):
    """Configure a temporary KEK for testing."""

    kek = os.urandom(32)
    kek_base64 = base64.b64encode(kek).decode("ascii")

    monkeypatch.setenv("KEK_BASE64", kek_base64)

    return kek


def test_valid_dek_produces_correct_lengths(test_kek):
    dek = os.urandom(32)

    result = wrap_file_key(dek)

    assert len(result["wrapped_dek"]) == 48
    assert len(result["nonce"]) == 12


def test_wrapping_same_dek_produces_different_nonces(test_kek):
    dek = os.urandom(32)

    first = wrap_file_key(dek)
    second = wrap_file_key(dek)

    assert first["nonce"] != second["nonce"]


def test_string_dek_raises_type_error(test_kek):
    with pytest.raises(TypeError):
        wrap_file_key("this is not bytes")


def test_wrong_length_dek_raises_value_error(test_kek):
    dek = os.urandom(16)

    with pytest.raises(ValueError):
        wrap_file_key(dek)


def test_missing_kek_raises_value_error(monkeypatch):
    monkeypatch.delenv("KEK_BASE64", raising=False)

    with pytest.raises(ValueError, match="not configured"):
        wrap_file_key(os.urandom(32))


def test_invalid_base64_kek_raises_value_error(monkeypatch):
    monkeypatch.setenv("KEK_BASE64", "not-valid-base64!")

    with pytest.raises(ValueError, match="not valid Base64"):
        wrap_file_key(os.urandom(32))


def test_wrong_length_kek_raises_value_error(monkeypatch):
    short_kek = os.urandom(16)
    encoded_kek = base64.b64encode(short_kek).decode("ascii")

    monkeypatch.setenv("KEK_BASE64", encoded_kek)

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        wrap_file_key(os.urandom(32))
