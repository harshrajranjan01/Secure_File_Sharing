import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile as StarletteUploadFile
from main import app

client = TestClient(app)

VALID_PDF = b"%PDF-1.7\nTest PDF content\n%%EOF"
CIPHERTEXT = b"encrypted-ciphertext-data"
FILE_NONCE = b"F" * 12
DEK = b"K" * 32
WRAPPED_DEK = b"W" * 48
KEY_NONCE = b"N" * 12
STORAGE_KEY = "a" * 64


@pytest.fixture
def mocked_upload():
    """Mock all external dependencies for upload endpoint tests."""

    with (
        patch(
            "backend.api.routes.files.encrypt_file_data",
            return_value={
                "ciphertext": CIPHERTEXT,
                "nonce": FILE_NONCE,
                "key": DEK,
            },
        ) as mock_encrypt,
        patch(
            "backend.api.routes.files.wrap_file_key",
            return_value={
                "wrapped_dek": WRAPPED_DEK,
                "nonce": KEY_NONCE,
            },
        ) as mock_wrap,
        patch(
            "backend.api.routes.files.store_encrypted_file",
            return_value=STORAGE_KEY,
        ) as mock_store,
        patch(
            "backend.api.routes.files.delete_encrypted_file",
        ) as mock_delete,
        patch(
            "backend.api.routes.files.save_encrypted_file_metadata",
            return_value=123,
        ) as mock_save,
    ):
        yield {
            "encrypt": mock_encrypt,
            "wrap": mock_wrap,
            "store": mock_store,
            "delete": mock_delete,
            "save": mock_save,
        }


def upload_pdf(content=VALID_PDF, filename="test.pdf",
               content_type="application/pdf"):
    return client.post(
        "/files/upload",
        files={
            "file": (filename, content, content_type),
        },
    )


def test_successful_upload(mocked_upload):
    response = upload_pdf()

    assert response.status_code == 201

    body = response.json()
    assert body["file_id"] == 123
    assert body["filename"] == "test.pdf"
    assert body["content_type"] == "application/pdf"
    assert body["size_bytes"] == len(VALID_PDF)
    assert body["encryption_status"] == "encrypted"

    mocked_upload["encrypt"].assert_called_once_with(VALID_PDF)
    mocked_upload["wrap"].assert_called_once_with(DEK)
    mocked_upload["store"].assert_called_once_with(CIPHERTEXT)

    mocked_upload["save"].assert_called_once_with(
        "test.pdf",
        "application/pdf",
        STORAGE_KEY,
        FILE_NONCE,
        WRAPPED_DEK,
        KEY_NONCE,
        len(VALID_PDF),
    )

    mocked_upload["delete"].assert_not_called()


def test_response_does_not_expose_sensitive_data(mocked_upload):
    response = upload_pdf()

    assert response.status_code == 201

    body = response.json()

    for sensitive_value in (
        DEK,
        CIPHERTEXT,
        WRAPPED_DEK,
        FILE_NONCE,
        KEY_NONCE,
    ):
        assert sensitive_value.decode() not in response.text

    assert "key" not in body
    assert "ciphertext" not in body
    assert "wrapped_dek" not in body
    assert "nonce" not in body


def test_invalid_pdf_signature_is_rejected(mocked_upload):
    response = upload_pdf(content=b"This is not a PDF")

    assert response.status_code == 400
    mocked_upload["encrypt"].assert_not_called()
    mocked_upload["wrap"].assert_not_called()
    mocked_upload["store"].assert_not_called()
    mocked_upload["save"].assert_not_called()


def test_wrong_mime_type_is_rejected(mocked_upload):
    response = upload_pdf(content_type="text/plain")

    assert response.status_code == 400
    mocked_upload["encrypt"].assert_not_called()
    mocked_upload["store"].assert_not_called()
    mocked_upload["save"].assert_not_called()


def test_empty_file_is_rejected(mocked_upload):
    response = upload_pdf(content=b"")

    assert response.status_code == 400
    mocked_upload["encrypt"].assert_not_called()
    mocked_upload["store"].assert_not_called()
    mocked_upload["save"].assert_not_called()


def test_oversized_file_is_rejected(mocked_upload):
    from backend.api.routes.files import MAX_FILE_SIZE

    oversized_pdf = b"%PDF-" + (
        b"A" * (MAX_FILE_SIZE + 1 - len(b"%PDF-"))
    )

    response = upload_pdf(content=oversized_pdf)

    assert response.status_code == 413
    mocked_upload["encrypt"].assert_not_called()
    mocked_upload["store"].assert_not_called()
    mocked_upload["save"].assert_not_called()


def test_storage_failure_returns_500(mocked_upload):
    mocked_upload["store"].side_effect = OSError("private details")

    response = upload_pdf()

    assert response.status_code == 500
    assert "private details" not in response.text
    mocked_upload["save"].assert_not_called()


def test_database_returns_none_and_deletes_ciphertext(mocked_upload):
    mocked_upload["save"].return_value = None

    response = upload_pdf()

    assert response.status_code == 500
    mocked_upload["delete"].assert_called_once_with(STORAGE_KEY)


def test_database_exception_deletes_ciphertext(mocked_upload):
    mocked_upload["save"].side_effect = RuntimeError("database details")

    response = upload_pdf()

    assert response.status_code == 500
    assert "database details" not in response.text
    mocked_upload["delete"].assert_called_once_with(STORAGE_KEY)


def test_cleanup_failure_does_not_mask_database_error(mocked_upload):
    mocked_upload["save"].side_effect = RuntimeError("database failure")
    mocked_upload["delete"].side_effect = OSError("cleanup failure")

    response = upload_pdf()

    assert response.status_code == 500
    assert "database failure" not in response.text
    assert "cleanup failure" not in response.text
    mocked_upload["delete"].assert_called_once_with(STORAGE_KEY)


def test_invalid_storage_identifier_returns_500(mocked_upload):
    mocked_upload["store"].return_value = "../invalid"

    response = upload_pdf()

    assert response.status_code == 500
    mocked_upload["save"].assert_not_called()
    mocked_upload["delete"].assert_not_called()


def test_key_wrapping_failure_returns_500(mocked_upload):
    mocked_upload["wrap"].side_effect = RuntimeError("secret details")

    response = upload_pdf()

    assert response.status_code == 500
    assert "secret details" not in response.text
    mocked_upload["store"].assert_not_called()
    mocked_upload["save"].assert_not_called()


def test_upload_is_closed_after_success(mocked_upload):
    with patch.object(
        StarletteUploadFile,
        "close",
        new_callable=AsyncMock,
    ) as mock_close:
        response = upload_pdf()

    assert response.status_code == 201
    assert mock_close.await_count >= 1


def test_upload_is_closed_after_validation_failure(mocked_upload):
    with patch.object(
        StarletteUploadFile,
        "close",
        new_callable=AsyncMock,
    ) as mock_close:
        response = upload_pdf(content=b"not a PDF")

    assert response.status_code == 400
    assert mock_close.await_count >= 1
