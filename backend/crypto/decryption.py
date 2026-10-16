from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")

    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")

    if len(nonce) != 12:
        raise ValueError("AES-GCM requires a 12-byte nonce")

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext
