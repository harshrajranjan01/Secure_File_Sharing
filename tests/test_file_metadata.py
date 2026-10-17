from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_valid_metadata_is_accepted():
    response = client.post(
        "/files/metadata",
        json={
            "filename": "report.pdf",
            "content_type": "application/pdf"
        }
    )

    assert response.status_code == 200

    assert response.json() == {
        "filename": "report.pdf",
        "content_type": "application/pdf"
    }


def test_missing_filename_is_rejected():
    response = client.post(
        "/files/metadata",
        json={
            "content_type": "application/pdf"
        }
    )

    assert response.status_code == 422


def test_missing_content_type_is_rejected():
    response = client.post(
        "/files/metadata",
        json={
            "filename": "report.pdf",
        }
    )

    assert response.status_code == 422


def test_empty_strings_are_rejected():
    response = client.post(
        "/files/metadata",
        json={
            "filename": "",
            "content_type": ""
        }
    )

    assert response.status_code == 422
