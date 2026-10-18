
import pytest
from unittest.mock import MagicMock, patch

from mysql.connector import Error

from backend.database.file_repository import save_encrypted_file_metadata


@pytest.fixture
def mock_db():
    """Create mocked MySQL connection and cursor."""

    with patch(
        "backend.database.file_repository.get_db_connection"
    ) as mock_connection_factory:

        connection = MagicMock()
        cursor = MagicMock()

        mock_connection_factory.return_value = connection
        connection.cursor.return_value = cursor
        cursor.lastrowid = 42

        yield mock_connection_factory, connection, cursor


@pytest.fixture
def sample_values():
    """Provide sample encrypted file metadata."""

    return {
        "filename": "report.pdf",
        "content_type": "application/pdf",
        "storage_key": "a" * 64,
        "file_nonce": b"F" * 12,
        "wrapped_dek": b"W" * 48,
        "key_nonce": b"K" * 12,
        "size_bytes": 1024,
    }


def test_successful_insert_returns_row_id(mock_db, sample_values):
    """Successful insert returns the inserted database row ID."""

    mock_factory, connection, cursor = mock_db

    result = save_encrypted_file_metadata(**sample_values)

    assert result == 42
    mock_factory.assert_called_once()
    cursor.execute.assert_called_once()
    connection.commit.assert_called_once()


def test_sql_parameter_order(mock_db, sample_values):
    """All seven values are passed to SQL in the correct order."""

    _, _, cursor = mock_db

    save_encrypted_file_metadata(**sample_values)

    actual_params = cursor.execute.call_args.args[1]

    expected_params = (
        sample_values["filename"],
        sample_values["content_type"],
        sample_values["storage_key"],
        sample_values["file_nonce"],
        sample_values["wrapped_dek"],
        sample_values["key_nonce"],
        sample_values["size_bytes"],
    )

    assert actual_params == expected_params


def test_connection_unavailable_returns_none(mock_db, sample_values):
    """Return None when a database connection is unavailable."""

    mock_factory, _, _ = mock_db
    mock_factory.return_value = None

    result = save_encrypted_file_metadata(**sample_values)

    assert result is None


def test_insert_failure_rolls_back(mock_db, sample_values):
    """An insert failure triggers rollback and returns None."""

    _, connection, cursor = mock_db
    cursor.execute.side_effect = Error("Insert failed")

    result = save_encrypted_file_metadata(**sample_values)

    assert result is None
    connection.rollback.assert_called_once()


def test_commit_failure_rolls_back(mock_db, sample_values):
    """A commit failure triggers rollback and returns None."""

    _, connection, cursor = mock_db
    connection.commit.side_effect = Error("Commit failed")

    result = save_encrypted_file_metadata(**sample_values)

    assert result is None
    connection.rollback.assert_called_once()
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_resources_are_closed_after_success(mock_db, sample_values):
    """Close the cursor and connection after a successful insert."""

    _, connection, cursor = mock_db

    save_encrypted_file_metadata(**sample_values)

    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_resources_are_closed_after_insert_failure(mock_db, sample_values):
    """Close the cursor and connection after an insert failure."""

    _, connection, cursor = mock_db
    cursor.execute.side_effect = Error("Insert failed")

    result = save_encrypted_file_metadata(**sample_values)

    assert result is None
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_cursor_creation_failure_returns_none(mock_db, sample_values):
    """Handle cursor creation failure without closing a nonexistent cursor."""

    _, connection, cursor = mock_db
    connection.cursor.side_effect = Error("Cursor creation failed")

    result = save_encrypted_file_metadata(**sample_values)

    assert result is None
    connection.rollback.assert_called_once()
    connection.close.assert_called_once()
    cursor.close.assert_not_called()
