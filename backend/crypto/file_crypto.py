from backend.crypto.key_generation import generate_file_key
from backend.crypto.encryption import encrypt_file
from backend.crypto.decryption import decrypt_file


def encrypt_file_data(data: bytes) -> dict:

    if not isinstance(data, bytes):
        raise TypeError("Data is not in bytes")
    
    key = generate_file_key()

    if not isinstance(key, bytes):
        raise TypeError("Key is not in Bytes")

    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")

    encrypted_data = encrypt_file(data, key)

    ciphertext = encrypted_data["ciphertext"]
    nonce = encrypted_data["nonce"]

    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "key": key
    }


def decrypt_file_data(encrypted_package: dict) -> bytes:

    if not isinstance(encrypted_package, dict):
        raise TypeError("Package must be dictionary")

    required_fields = ["ciphertext", "nonce", "key"]

    for field in required_fields:
        if field not in encrypted_package:
            raise ValueError(f"Package is missing required field: {field}")

    ciphertext = encrypted_package["ciphertext"]
    nonce = encrypted_package["nonce"]
    key = encrypted_package["key"]

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be byte")

    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")

    if len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes")

    return decrypt_file(ciphertext, key, nonce)
