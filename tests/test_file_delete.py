
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


@patch("backend.api.routes.files.delete_encrypted_file")
@patch("backend.api.routes.files.delete_file_metadata")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_delete_file_success(
    mock_get_metadata,
    mock_delete_metadata,
    mock_delete_storage,
):
    mock_get_metadata.return_value = {
        "id": 1,
        "filename": "test.pdf",
        "storage_key": "a" * 64,
    }
    mock_delete_metadata.return_value = True

    response = client.delete("/files/1")

    assert response.status_code == 200
    assert response.json()["message"] == "File deleted successfully."
    assert response.json()["file_id"] == 1

    mock_get_metadata.assert_called_once_with(1)
    mock_delete_metadata.assert_called_once_with(1)
    mock_delete_storage.assert_called_once_with("a" * 64)


@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_delete_file_not_found(mock_get_metadata):
    mock_get_metadata.return_value = None

    response = client.delete("/files/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "File Not found"


@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_delete_file_invalid_id(mock_get_metadata):
    response = client.delete("/files/0")

    assert response.status_code == 422
    mock_get_metadata.assert_not_called()


@patch("backend.api.routes.files.delete_file_metadata")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_delete_file_database_failure(
    mock_get_metadata,
    mock_delete_metadata,
):
    mock_get_metadata.return_value = {
        "id": 1,
        "filename": "test.pdf",
        "storage_key": "a" * 64,
    }
    mock_delete_metadata.return_value = False

    response = client.delete("/files/1")

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to delete file metadata"


@patch("backend.api.routes.files.delete_encrypted_file")
@patch("backend.api.routes.files.delete_file_metadata")
@patch("backend.api.routes.files.get_encrypted_file_metadata")
def test_delete_file_storage_failure(
    mock_get_metadata,
    mock_delete_metadata,
    mock_delete_storage,
):
    mock_get_metadata.return_value = {
        "id": 1,
        "filename": "test.pdf",
        "storage_key": "a" * 64,
    }
    mock_delete_metadata.return_value = True
    mock_delete_storage.side_effect = OSError("Internal filesystem details")

    response = client.delete("/files/1")

    assert response.status_code == 500
    assert "Internal filesystem details" not in response.text
    assert "cleanup failed" in response.json()["detail"]

    mock_delete_metadata.assert_called_once_with(1)
    mock_delete_storage.assert_called_once_with("a" * 64)
