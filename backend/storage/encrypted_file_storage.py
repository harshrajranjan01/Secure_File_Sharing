
import secrets
from pathlib import Path


# Store files outside the public/static directory.
STORAGE_DIR = Path(__file__).resolve().parents[2] / "private_storage"


def store_encrypted_file(ciphertext: bytes) -> str:
    """Store encrypted bytes and return a random storage identifier."""

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")

    if not ciphertext:
        raise ValueError("Ciphertext must not be empty.")

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    # Generate an unpredictable file identifier on the server.
    storage_key = secrets.token_hex(32)

    # Construct the path using the server-generated identifier,
    # never directly from user input. This helps prevent path traversal.
    file_path = STORAGE_DIR / f"{storage_key}.enc"

    with file_path.open("xb") as encrypted_file:
        encrypted_file.write(ciphertext)

    return storage_key


def delete_encrypted_file(storage_key: str) -> None:
    """Delete a stored ciphertext file, ignoring missing files."""

    if not isinstance(storage_key, str):
        raise TypeError("Storage key must be a string.")

    if (
        len(storage_key) != 64
        or any(character not in "0123456789abcdef" for character in storage_key)
    ):
        raise ValueError("Invalid storage key.")

    file_path = STORAGE_DIR / f"{storage_key}.enc"

    try:
        file_path.unlink()
    except FileNotFoundError:
        # Already deleted or never existed; cleanup is complete.
        pass


def read_encrypted_file(storage_key: str) -> bytes:

    if (
        not isinstance(storage_key, str)
        or len(storage_key) != 64
        or any(char not in "0123456789abcdef" for char in storage_key)
    ):
        raise ValueError("Invalid Storage Key")

    file_path=STORAGE_DIR / f"{storage_key}.enc"

    return   file_path.read_bytes() #its actually ciphertext