
import pytest
from cryptography.exceptions import InvalidTag

from backend.crypto.file_crypto import encrypt_file_data, decrypt_file_data


def test_complete_round_trip():
    original_data = b"Hello, This is Harsh Raj Ranjan"

    encrypted_package = encrypt_file_data(original_data)
    decrypted_data = decrypt_file_data(encrypted_package)

    assert decrypted_data == original_data


def test_empty_data():
    original_data = b""

    encrypted_package = encrypt_file_data(original_data)
    decrypted_data = decrypt_file_data(encrypted_package)

    assert decrypted_data == original_data


def test_binary_data():
    original_data = bytes(range(256))

    encrypted_package = encrypt_file_data(original_data)
    decrypted_data = decrypt_file_data(encrypted_package)

    assert decrypted_data == original_data


def test_tampered_package():
    original_data = b"Hi this is Harsh"

    encrypted_package = encrypt_file_data(original_data)

    tampered_ciphertext = bytearray(encrypted_package["ciphertext"])
    tampered_ciphertext[0] ^= 1

    encrypted_package["ciphertext"] = bytes(tampered_ciphertext)

    with pytest.raises(InvalidTag):
        decrypt_file_data(encrypted_package)

def test_wrong_key():
    original_data = b"Hi this is Harsh"
    encrypted_package = encrypt_file_data(original_data)
    
    encrypted_package["key"] = encrypt_file_data(b"Another file")["key"]

    # Act and Assert
    with pytest.raises(InvalidTag):
        decrypt_file_data(encrypted_package)


def test_missing_nonce():
    # Arrange
    encrypted_package = encrypt_file_data(b"Secret file data")
    del encrypted_package["nonce"]

    # Act and Assert
    with pytest.raises(ValueError, match="missing required field"):
        decrypt_file_data(encrypted_package)


def test_invalid_key_length():
    # Arrange
    encrypted_package = encrypt_file_data(b"Secret file data")
    encrypted_package["key"] = b"short"

    # Act and Assert
    with pytest.raises(ValueError, match="32 bytes"):
        decrypt_file_data(encrypted_package)


def test_invalid_nonce_length():
    # Arrange
    encrypted_package = encrypt_file_data(b"Secret file data")
    encrypted_package["nonce"] = b"short"

    # Act and Assert
    with pytest.raises(ValueError, match="12 bytes"):
        decrypt_file_data(encrypted_package)

def test_encrypt_file_data_invalid_input():
    with pytest.raises(TypeError):
        encrypt_file_data("this is not bytes")


def test_decrypt_file_data_invalid_input():
    with pytest.raises(TypeError):
        decrypt_file_data("this is not a dictionary")
