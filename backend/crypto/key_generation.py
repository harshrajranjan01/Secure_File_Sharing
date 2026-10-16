from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_file_key() -> bytes:

    key = AESGCM.generate_key(bit_length=256)

    return key
