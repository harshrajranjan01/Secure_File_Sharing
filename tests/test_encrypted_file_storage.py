
import pytest

from backend.storage import encrypted_file_storage as storage


@pytest.fixture
def storage_dir(tmp_path, monkeypatch):
    """Use a temporary directory instead of real file storage."""

    test_directory = tmp_path / "private_storage"
    monkeypatch.setattr(storage, "STORAGE_DIR", test_directory)

    return test_directory


def test_store_encrypted_file(storage_dir):
    ciphertext = b"\x00encrypted\xffdata"

    storage_key = storage.store_encrypted_file(ciphertext)

    file_path = storage_dir / f"{storage_key}.enc"

    assert len(storage_key) == 64
    assert all(char in "0123456789abcdef" for char in storage_key)
    assert file_path.exists()
    assert file_path.read_bytes() == ciphertext


def test_store_rejects_string(storage_dir):
    with pytest.raises(TypeError):
        storage.store_encrypted_file("not bytes")


def test_store_rejects_empty_bytes(storage_dir):
    with pytest.raises(ValueError):
        storage.store_encrypted_file(b"")


def test_two_files_receive_different_identifiers(storage_dir):
    first_key = storage.store_encrypted_file(b"first ciphertext")
    second_key = storage.store_encrypted_file(b"second ciphertext")

    assert first_key != second_key

    assert (storage_dir / f"{first_key}.enc").read_bytes() == (
        b"first ciphertext"
    )
    assert (storage_dir / f"{second_key}.enc").read_bytes() == (
        b"second ciphertext"
    )


def test_delete_stored_file(storage_dir):
    ciphertext = b"encrypted content"
    storage_key = storage.store_encrypted_file(ciphertext)

    file_path = storage_dir / f"{storage_key}.enc"
    assert file_path.exists()

    storage.delete_encrypted_file(storage_key)

    assert not file_path.exists()


def test_delete_nonexistent_file_succeeds(storage_dir):
    storage.delete_encrypted_file("a" * 64)


@pytest.mark.parametrize(
    "invalid_key",
    [
        "a" * 63,  # Wrong length
        "A" * 64,  # Uppercase characters
        "../" + "a" * 61,  # Path separators
        "a" * 63 + "/",  # Trailing path separator
    ],
)
def test_delete_rejects_invalid_identifiers(storage_dir, invalid_key):
    with pytest.raises(ValueError):
        storage.delete_encrypted_file(invalid_key)


def test_read_rejects_non_string_identifier(storage_dir):
    with pytest.raises(ValueError):
        storage.read_encrypted_file(123)


def test_store_does_not_overwrite_existing_file(storage_dir, monkeypatch):
    original_ciphertext = b"original encrypted content"
    replacement_ciphertext = b"replacement encrypted content"

    storage_key = "a" * 64
    existing_file = storage_dir / f"{storage_key}.enc"

    storage_dir.mkdir(parents=True, exist_ok=True)
    existing_file.write_bytes(original_ciphertext)

    # Force the storage function to use the existing identifier.
    monkeypatch.setattr(storage.secrets, "token_hex", lambda n: storage_key)

    with pytest.raises(FileExistsError):
        storage.store_encrypted_file(replacement_ciphertext)

    # Confirm that the original file was not overwritten.
    assert existing_file.read_bytes() == original_ciphertext



# ---------------------------------------------------------------------------
# Read Encrypted File Tests
# ---------------------------------------------------------------------------
def test_read_encrypted_file(storage_dir):
    ciphertext = b"\x00encrypted\xffdata"
    storage_key = storage.store_encrypted_file(ciphertext)

    result = storage.read_encrypted_file(storage_key)

    assert result == ciphertext
    assert isinstance(result, bytes)


@pytest.mark.parametrize(
    "invalid_key",
    [
        "a" * 63,  # Wrong length
        "a" * 65,  # Wrong length
        "A" * 64,  # Uppercase characters
        "g" * 64,  # Non-hexadecimal character
        "../" + "a" * 61,  # Path traversal
        "a" * 63 + "/",  # Trailing path separator
    ],
)
def test_read_rejects_invalid_identifiers(storage_dir, invalid_key):
    with pytest.raises(ValueError):
        storage.read_encrypted_file(invalid_key)


def test_read_nonexistent_file(storage_dir):
    with pytest.raises(FileNotFoundError):
        storage.read_encrypted_file("a" * 64)


