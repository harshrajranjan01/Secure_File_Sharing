
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)

DOWNLOAD_URL = "/files/{}/download"

VALID_METADATA = {
    "storage_key": "a" * 64,
    "file_nonce": b"f" * 12,
    "wrapped_dek": b"w" * 48,
    "key_nonce": b"k" * 12,
}

CIPHERTEXT = b"encrypted-pdf-data"
ORIGINAL_PDF = b"%PDF-1.4\noriginal PDF content"


@patch("backend.api.routes.files.unwrap_file_key")
@patch("backend.api.routes.files.decrypt_file_data")
@patch("backend.api.routes.files.read_encrypted_file")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_download_file_success(
    mock_get_metadata,
    mock_read_file,
    mock_decrypt,
    mock_unwrap_key,
):
    """Return the original PDF for a valid encrypted file."""

    mock_get_metadata.return_value = VALID_METADATA
    mock_read_file.return_value = CIPHERTEXT
    mock_unwrap_key.return_value = b"x" * 32
    mock_decrypt.return_value = ORIGINAL_PDF

    response = client.get(DOWNLOAD_URL.format(1))

    assert response.status_code == 200
    assert response.content == ORIGINAL_PDF
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == (
        'attachment; filename="download.pdf"'
    )

    mock_get_metadata.assert_called_once_with(1)
    mock_read_file.assert_called_once_with(VALID_METADATA["storage_key"])
    mock_unwrap_key.assert_called_once()
    mock_decrypt.assert_called_once()

    # The response must not expose the ciphertext or wrapped DEK.
    assert CIPHERTEXT not in response.content
    assert VALID_METADATA["wrapped_dek"] not in response.content


@patch("backend.api.routes.files.read_encrypted_file")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_download_file_not_found(mock_get_metadata, mock_read_file):
    """Return 404 when no metadata exists for the requested file."""

    mock_get_metadata.return_value = None

    response = client.get(DOWNLOAD_URL.format(999))

    assert response.status_code == 404
    assert response.json()["detail"] == "File not found"

    mock_get_metadata.assert_called_once_with(999)
    mock_read_file.assert_not_called()


@pytest.mark.parametrize(
    "missing_field",
    ["storage_key", "file_nonce", "wrapped_dek", "key_nonce"],
)
@patch("backend.api.routes.files.read_encrypted_file")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_download_file_missing_encryption_metadata(
    mock_get_metadata,
    mock_read_file,
    missing_field,
):
    """Return 409 when a required encryption field is NULL."""

    metadata = VALID_METADATA.copy()
    metadata[missing_field] = None
    mock_get_metadata.return_value = metadata

    response = client.get(DOWNLOAD_URL.format(1))

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "File is missing required encryption metadata"
    )

    mock_get_metadata.assert_called_once_with(1)
    mock_read_file.assert_not_called()


@patch("backend.api.routes.files.read_encrypted_file")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_download_file_missing_from_storage(
    mock_get_metadata,
    mock_read_file,
):
    """Return 404 when the encrypted file is absent from storage."""

    mock_get_metadata.return_value = VALID_METADATA
    mock_read_file.side_effect = FileNotFoundError

    response = client.get(DOWNLOAD_URL.format(1))

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Encrypted file not found in storage"
    )

    mock_get_metadata.assert_called_once_with(1)
    mock_read_file.assert_called_once_with(VALID_METADATA["storage_key"])


@patch("backend.api.routes.files.read_encrypted_file")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_download_file_storage_error(
    mock_get_metadata,
    mock_read_file,
):
    """Return 500 when storage raises an unexpected exception."""

    mock_get_metadata.return_value = VALID_METADATA
    mock_read_file.side_effect = OSError("Internal storage failure")

    response = client.get(DOWNLOAD_URL.format(1))

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Failed to retrieve encrypted file"
    )

    mock_get_metadata.assert_called_once_with(1)
    mock_read_file.assert_called_once_with(VALID_METADATA["storage_key"])


@pytest.mark.parametrize("invalid_file_id", [0, -1, -100])
@patch("backend.api.routes.files.get_encrypted_file_metadata")
@patch("backend.api.routes.files.read_encrypted_file")
def test_download_file_invalid_id(
    mock_read_file,
    mock_get_metadata,
    invalid_file_id,
):
    """Reject non-positive IDs before accessing metadata or storage."""

    response = client.get(DOWNLOAD_URL.format(invalid_file_id))

    assert response.status_code == 422
    mock_get_metadata.assert_not_called()
    mock_read_file.assert_not_called()
