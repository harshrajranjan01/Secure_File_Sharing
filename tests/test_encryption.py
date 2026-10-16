import pytest

from backend.crypto.key_generation import generate_file_key
from backend.crypto.encryption import encrypt_file


def test_ciphertext_and_nonce_is_in_dictionary():
    key = generate_file_key()
    data = b"Hi this is Harsh Raj Ranjan"
    result = encrypt_file(data, key)

    assert "ciphertext" in result
    assert "nonce" in result


def test_length_key_and_nonce():
    key = generate_file_key()
    data = b"Hi this is Harsh Raj Ranjan"
    result = encrypt_file(data, key)

    assert isinstance(result["nonce"], bytes)
    assert len(result["nonce"]) == 12


def encrypting_same_data_produce_different_nonce():
    key = generate_file_key()
    data = b"Hi this is Harsh Raj Ranjan"
    result1 = encrypt_file(data, key)
    result2 = encrypt_file(data, key)

    assert result1["nonce"] != result2["nonce"]


def test_encrypt_empty_data():
    key = generate_file_key()
    data = b""
    result = encrypt_file(data, key)
    assert isinstance(result["ciphertext"], bytes)
    assert len(result["ciphertext"]) == 16


def test_encrypt_binary_data():
    key = generate_file_key()
    data = bytes([0, 1, 2, 255, 128, 0, 10])
    result = encrypt_file(data, key)

    assert isinstance(result["ciphertext"], bytes)
    assert len(result["ciphertext"]) == len(data) + 16



def test_invalid_key_length_raises_value_error():
    data = b"Test data"
    invalid_key = b"short"

    with pytest.raises(ValueError):
        encrypt_file(data, invalid_key)


def test_non_byte_data_raises_type_error():
    key = generate_file_key()
    data = "This is a string, not bytes"

    with pytest.raises(TypeError):
        encrypt_file(data, key)


def test_non_byte_key_raises_type_error():
    data = b"Test data"
    key = "this is not bytes"

    with pytest.raises(TypeError):
        encrypt_file(data, key)

