import pytest
from cryptography.exceptions import InvalidTag


from backend.crypto.key_generation import generate_file_key
from backend.crypto.decryption import decrypt_file
from backend.crypto.encryption import encrypt_file


def test_decrypt_file():
    plaintext = b"Hello This is Harsh Raj"
    key = generate_file_key()

    encrypted_data = encrypt_file(plaintext, key)

    ciphertext = encrypted_data["ciphertext"]
    nonce = encrypted_data["nonce"]

    decrypted_data = decrypt_file(ciphertext, key, nonce)

    assert plaintext == decrypted_data


def test_decrypt_empty_file():
    plaintext = b""
    key = generate_file_key()

    encrypted_data = encrypt_file(plaintext, key)
    ciphertext = encrypted_data["ciphertext"]
    nonce = encrypted_data["nonce"]

    decrypted_data = decrypt_file(ciphertext, key, nonce)

    assert plaintext == decrypted_data


def test_decrpt_with_wrong_key():
    plaintext = b""
    key = generate_file_key()
    wrong_key = generate_file_key()

    encrypted_data = encrypt_file(plaintext, key)
    ciphertext = encrypted_data["ciphertext"]
    nonce = encrypted_data["nonce"]

    with pytest.raises(InvalidTag):
        decrypted_data = decrypt_file(ciphertext, wrong_key, nonce)


def test_decrypt_with_modified_ciphertext():
    plaintext = b"Hello This is Harsh Raj"
    key = generate_file_key()

    encrypted_data = encrypt_file(plaintext, key)
    ciphertext = encrypted_data["ciphertext"]
    nonce = encrypted_data["nonce"]

    modified_ciphertext = bytes([ciphertext[0] ^ 1])+ciphertext[1:]

    with pytest.raises(InvalidTag):
        decrypt_file(modified_ciphertext, key, nonce)


def test_decrypt_rejects_invalid_key_length():
    with pytest.raises(ValueError):
        decrypt_file(b"ciphertext", b"short", b"123456789101112")


def test_decrypt_rejects_wrong_ciphertext_type():
    with pytest.raises(TypeError):
        decrypt_file("ciphertext", b"k" * 32, b"123456789012")


def test_decrypt_rejects_wrong_key_type():
    with pytest.raises(TypeError):
        decrypt_file(b"ciphertext", "k" * 32, b"123456789012")


def test_decrypt_rejects_wrong_nonce_type():
    with pytest.raises(TypeError):
        decrypt_file(b"ciphertext", b"k" * 32, "123456789012")


def test_decrypt_with_wrong_nonce():
    # Arrange
    plaintext = b"Hello, Secure File Sharing!"
    key = generate_file_key()

    encrypted = encrypt_file(plaintext, key)
    ciphertext = encrypted["ciphertext"]
    nonce = encrypted["nonce"]

    # Create a different nonce that is still 12 bytes long.
    wrong_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]

    # Act and Assert
    with pytest.raises(InvalidTag):
        decrypt_file(ciphertext, key, wrong_nonce)
