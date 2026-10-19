from datetime import datetime
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


@patch("backend.api.routes.files.list_files_metadata")
def test_get_files_success(mock_list_files_metadata):
    """Test that GET /files returns file metadata."""

    mock_list_files_metadata.return_value = [
        {
            "id": 1,
            "filename": "document.pdf",
            "content_type": "application/pdf",
            "created_at": datetime(2026, 10, 19, 12, 0, 0),
            "size_bytes": 2048,
        }
    ]

    response = client.get("/files")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": 1,
            "filename": "document.pdf",
            "content_type": "application/pdf",
            "created_at": "2026-10-19T12:00:00",
            "size_bytes": 2048,
        }
    ]

    mock_list_files_metadata.assert_called_once()


@patch("backend.api.routes.files.list_files_metadata")
def test_get_files_empty(mock_list_files_metadata):
    """Test that GET /files returns an empty list when no files exist."""

    mock_list_files_metadata.return_value = []

    response = client.get("/files")

    assert response.status_code == 200
    assert response.json() == []