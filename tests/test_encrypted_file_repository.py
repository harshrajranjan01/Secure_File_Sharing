
import pytest
from unittest.mock import MagicMock, patch

from mysql.connector import Error

from backend.database.file_repository import (
    save_encrypted_file_metadata,
    get_encrypted_file_metadata,
)


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



# --------------------------------------------------
# Tests for get_encrypted_file_metadata()
# --------------------------------------------------

@pytest.fixture
def sample_encrypted_record():
    """Provide a sample database record."""

    return {
        "id": 42,
        "filename": "report.pdf",
        "content_type": "application/pdf",
        "storage_key": "a" * 64,
        "file_nonce": b"F" * 12,
        "wrapped_dek": b"W" * 48,
        "key_nonce": b"K" * 12,
        "size_bytes": 1024,
    }


def test_get_metadata_successful_retrieval(
    mock_db,
    sample_encrypted_record,
):
    """Return the retrieved record as a dictionary."""

    _, connection, cursor = mock_db
    cursor.fetchone.return_value = sample_encrypted_record

    result = get_encrypted_file_metadata(42)

    assert result == sample_encrypted_record
    connection.cursor.assert_called_once_with(dictionary=True)
    cursor.execute.assert_called_once()
    assert cursor.execute.call_args.args[1] == (42,)

    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_get_metadata_uses_parameterized_query(
    mock_db,
    sample_encrypted_record,
):
    """Pass the file ID separately from the SQL query."""

    _, _, cursor = mock_db
    cursor.fetchone.return_value = sample_encrypted_record

    get_encrypted_file_metadata(42)

    query, params = cursor.execute.call_args.args

    assert "WHERE id = %s" in query
    assert params == (42,)


def test_get_metadata_missing_record(mock_db):
    """Return None when the requested record does not exist."""

    _, connection, cursor = mock_db
    cursor.fetchone.return_value = None

    result = get_encrypted_file_metadata(999)

    assert result is None
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "file_id",
    [
        0,
        -1,
        -42,
        "42",
        42.5,
        True,
        False,
        None,
    ],
)
def test_get_metadata_rejects_invalid_file_id(file_id):
    """Reject invalid IDs before opening a database connection."""

    with patch(
        "backend.database.file_repository.get_db_connection"
    ) as mock_factory:

        result = get_encrypted_file_metadata(file_id)

    assert result is None
    mock_factory.assert_not_called()


def test_get_metadata_connection_unavailable(mock_db):
    """Return None if no database connection is available."""

    mock_factory, _, _ = mock_db
    mock_factory.return_value = None

    result = get_encrypted_file_metadata(42)

    assert result is None


def test_get_metadata_connection_failure():
    """Return None if establishing the connection raises a database error."""

    with patch(
        "backend.database.file_repository.get_db_connection",
        side_effect=Error("Connection failed"),
    ):
        result = get_encrypted_file_metadata(42)

    assert result is None


def test_get_metadata_cursor_creation_failure(mock_db):
    """Handle cursor creation failure and close the connection."""

    _, connection, cursor = mock_db
    connection.cursor.side_effect = Error("Cursor creation failed")

    result = get_encrypted_file_metadata(42)

    assert result is None
    connection.rollback.assert_called_once()
    connection.close.assert_called_once()
    cursor.close.assert_not_called()


def test_get_metadata_query_failure(mock_db):
    """Roll back and clean up after a query failure."""

    _, connection, cursor = mock_db
    cursor.execute.side_effect = Error("Query failed")

    result = get_encrypted_file_metadata(42)

    assert result is None
    connection.rollback.assert_called_once()
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_get_metadata_fetch_failure(mock_db):
    """Roll back and clean up if fetching the record fails."""

    _, connection, cursor = mock_db
    cursor.fetchone.side_effect = Error("Fetch failed")

    result = get_encrypted_file_metadata(42)

    assert result is None
    connection.rollback.assert_called_once()
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_get_metadata_rollback_failure(mock_db):
    """A rollback failure must not prevent resource cleanup."""

    _, connection, cursor = mock_db

    cursor.execute.side_effect = Error("Query failed")
    connection.rollback.side_effect = Error("Rollback failed")

    result = get_encrypted_file_metadata(42)

    assert result is None
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_get_metadata_binary_fields_unchanged(
    mock_db,
    sample_encrypted_record,
):
    """Return binary encryption fields without modification."""

    _, _, cursor = mock_db
    cursor.fetchone.return_value = sample_encrypted_record

    result = get_encrypted_file_metadata(42)

    assert result["file_nonce"] == b"F" * 12
    assert result["wrapped_dek"] == b"W" * 48
    assert result["key_nonce"] == b"K" * 12

    assert isinstance(result["file_nonce"], bytes)
    assert isinstance(result["wrapped_dek"], bytes)
    assert isinstance(result["key_nonce"], bytes)


def test_get_metadata_legacy_record(mock_db):
    """Return legacy metadata even when encryption fields are NULL."""

    _, _, cursor = mock_db

    legacy_record = {
        "id": 3,
        "filename": "legacy.pdf",
        "content_type": "application/pdf",
        "storage_key": None,
        "file_nonce": None,
        "wrapped_dek": None,
        "key_nonce": None,
        "size_bytes": None,
    }

    cursor.fetchone.return_value = legacy_record

    result = get_encrypted_file_metadata(3)

    assert result == legacy_record
    assert result["storage_key"] is None
    assert result["file_nonce"] is None
    assert result["wrapped_dek"] is None
    assert result["key_nonce"] is None


@pytest.mark.parametrize(
    "failure_point",
    ["execute", "fetchone"],
)
def test_get_metadata_resources_closed_after_failure(
    mock_db,
    failure_point,
):
    """Close both resources after query or fetch errors."""

    _, connection, cursor = mock_db

    if failure_point == "execute":
        cursor.execute.side_effect = Error("Query failed")
    else:
        cursor.fetchone.side_effect = Error("Fetch failed")

    result = get_encrypted_file_metadata(42)

    assert result is None
    cursor.close.assert_called_once()
    connection.close.assert_called_once()


def test_get_metadata_cleanup_error_does_not_mask_result(
    mock_db,
    sample_encrypted_record,
):
    """A cursor close error must not mask successful retrieval."""

    _, connection, cursor = mock_db
    cursor.fetchone.return_value = sample_encrypted_record
    cursor.close.side_effect = Error("Cursor close failed")

    result = get_encrypted_file_metadata(42)

    assert result == sample_encrypted_record
    connection.close.assert_called_once()


def test_get_metadata_connection_close_error_does_not_mask_result(
    mock_db,
    sample_encrypted_record,
):
    """A connection close error must not mask successful retrieval."""

    _, connection, cursor = mock_db
    cursor.fetchone.return_value = sample_encrypted_record
    connection.close.side_effect = Error("Connection close failed")

    result = get_encrypted_file_metadata(42)

    assert result == sample_encrypted_record
    cursor.close.assert_called_once()
