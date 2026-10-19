
from fastapi.testclient import TestClient

from main import app
from backend.api.routes import files as file_routes
from backend.storage import encrypted_file_storage as storage


client = TestClient(app)

UPLOAD_URL = "/files/upload"
DOWNLOAD_URL = "/files/{}/download"

ORIGINAL_PDF = (
    b"%PDF-1.4\n"
    b"Secure File Sharing integration test\n"
    b"%%EOF"
)


def test_upload_and_download_file_round_trip(tmp_path, monkeypatch):
    """
    Upload a PDF, store it encrypted, download it,
    and verify that the original bytes are recovered.
    """

    # 1. Use temporary storage instead of the real storage directory.
    monkeypatch.setattr(storage, "STORAGE_DIR", tmp_path)

    # 2. Use an in-memory repository instead of MySQL.
    metadata_store = {}
    next_file_id = 1

    def fake_save_metadata(
        filename,
        content_type,
        storage_key,
        file_nonce,
        wrapped_dek,
        key_nonce,
        size_bytes,
    ):
        nonlocal next_file_id

        file_id = next_file_id
        next_file_id += 1

        metadata_store[file_id] = {
            "filename": filename,
            "content_type": content_type,
            "storage_key": storage_key,
            "file_nonce": file_nonce,
            "wrapped_dek": wrapped_dek,
            "key_nonce": key_nonce,
            "size_bytes": size_bytes,
        }

        return file_id

    def fake_get_metadata(file_id):
        return metadata_store.get(file_id)

    monkeypatch.setattr(
        file_routes,
        "save_encrypted_file_metadata",
        fake_save_metadata,
    )
    monkeypatch.setattr(
        file_routes,
        "get_encrypted_file_metadata",
        fake_get_metadata,
    )

    # 3. Upload the original PDF.
    upload_response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "integration-test.pdf",
                ORIGINAL_PDF,
                "application/pdf",
            )
        },
    )

    assert upload_response.status_code == 201, upload_response.text

    upload_data = upload_response.json()

    assert upload_data["message"] == (
        "PDF validated and encrypted successfully"
    )
    assert upload_data["filename"] == "integration-test.pdf"
    assert upload_data["content_type"] == "application/pdf"
    assert upload_data["size_bytes"] == len(ORIGINAL_PDF)
    assert upload_data["encryption_status"] == "encrypted"

    file_id = upload_data["file_id"]
    assert file_id in metadata_store

    # 4. Verify the required encryption metadata was saved.
    metadata = metadata_store[file_id]

    assert metadata["storage_key"]
    assert metadata["file_nonce"]
    assert metadata["wrapped_dek"]
    assert metadata["key_nonce"]

    # 5. Verify the actual stored file contains ciphertext,
    # not the original plaintext PDF.
    ciphertext = storage.read_encrypted_file(
        metadata["storage_key"]
    )

    assert isinstance(ciphertext, bytes)
    assert ciphertext != ORIGINAL_PDF
    assert ORIGINAL_PDF not in ciphertext

    # 6. Download the file using the returned file ID.
    download_response = client.get(
        DOWNLOAD_URL.format(file_id)
    )

    assert download_response.status_code == 200
    assert download_response.content == ORIGINAL_PDF

    assert download_response.headers["content-type"] == (
        "application/pdf"
    )
    assert download_response.headers["content-disposition"] == (
        'attachment; filename="download.pdf"'
    )

    # 7. Verify the download response doesn't expose encryption data.
    assert ciphertext not in download_response.content
    assert metadata["wrapped_dek"] not in download_response.content
