import os
import base64
import binascii

from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()


def _load_kek() -> bytes:
    """load and validate the KEK from the environment"""

    kek_base64 = os.getenv("KEK_BASE64")

    if not kek_base64:
        raise ValueError("KEK_BASE64 is not configured")

    try:
        kek = base64.b64decode(kek_base64, validate=True)

    except (binascii.Error, ValueError) as exc:
        raise ValueError("KEK_BASE64 is not valid Base64") from exc

    if len(kek) != 32:
        raise ValueError("KEK must decode to exactly 32 bytes")

    return kek


def wrap_file_key(dek: bytes) -> dict:
    """Encrypt a 32-bytes DEK using AES-256-GCM and the KEK."""

    if not isinstance(dek, bytes):
        raise TypeError("DEK must be bytes")

    if len(dek) != 32:
        raise ValueError("DEK must be exactly 32 bytes")

    kek = _load_kek()

    # Generate a fresh, unpredictable 12-bytes nonce
    nonce = os.urandom(12)

    # Encrpt the DEK using the seperate KEK
    aesgcm = AESGCM(kek)
    wrapped_dek = aesgcm.encrypt(nonce, dek, None)

    return {
        "wrapped_dek": wrapped_dek,
        "nonce": nonce,
    }
