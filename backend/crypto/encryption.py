import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(data: bytes, key: bytes) -> dict:

    if not isinstance(data, bytes):
        raise TypeError("Data must be byte")

    if not isinstance(key, bytes):
        raise TypeError("Key must be byte")

    if len(key) != 32:
        raise ValueError("AES-256 requires a 32 byte key")

    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, data, None)

    return {
        "ciphertext": ciphertext,
        "nonce": nonce
    }
