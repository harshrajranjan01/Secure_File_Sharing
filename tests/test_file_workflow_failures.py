
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)

UPLOAD_URL = "/files/upload"

VALID_PDF = b"%PDF-1.4\nTest PDF content\n%%EOF"


def test_upload_invalid_pdf():
    """Reject a file that does not have a PDF signature."""

    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "invalid.pdf",
                b"This is not a PDF",
                "application/pdf",
            )
        },
    )

    assert response.status_code in (400, 415, 422)


def test_upload_empty_file():
    """Reject an empty upload."""

    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "empty.pdf",
                b"",
                "application/pdf",
            )
        },
    )

    assert response.status_code in (400, 413, 415, 422)


def test_upload_oversized_file():
    """Reject a PDF exceeding the configured 10 MiB limit."""

    oversized_pdf = b"%PDF-" + b"A" * (10 * 1024 * 1024)

    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "oversized.pdf",
                oversized_pdf,
                "application/pdf",
            )
        },
    )

    assert response.status_code == 413


@patch("backend.api.routes.files.save_encrypted_file_metadata")
def test_upload_metadata_persistence_failure(mock_save_metadata):
    """Return an error if metadata cannot be persisted."""

    mock_save_metadata.side_effect = RuntimeError(
        "Simulated database failure"
    )

    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "test.pdf",
                VALID_PDF,
                "application/pdf",
            )
        },
    )

    assert response.status_code >= 400
