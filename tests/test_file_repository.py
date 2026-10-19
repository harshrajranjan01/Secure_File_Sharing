
from backend.database.file_repository import delete_file_metadata
import uuid
from unittest.mock import MagicMock, patch

import mysql.connector
import pytest

from backend.database.connection import get_db_connection
from backend.database.file_repository import save_file_metadata


def test_successful_insert_and_persistence():
    """Verify that metadata is inserted and persisted in MySQL."""

    filename = f"report_{uuid.uuid4().hex}.pdf"
    content_type = "application/pdf"

    connection = get_db_connection()

    if connection is None:
        pytest.fail("MySQL connection is unavailable.")

    file_id = None
    cursor = None

    try:
        # Insert metadata using the repository function
        file_id = save_file_metadata(filename, content_type)

        assert file_id is not None
        assert isinstance(file_id, int)
        assert file_id > 0

        # Verify the record using its ID
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT filename, content_type
            FROM files
            WHERE id = %s
            """,
            (file_id,),
        )

        record = cursor.fetchone()

        assert record is not None
        assert record[0] == filename
        assert record[1] == content_type

    finally:
        # Delete the test record
        try:
            if file_id is not None:
                if cursor is None:
                    cursor = connection.cursor()

                cursor.execute(
                    "DELETE FROM files WHERE id = %s",
                    (file_id,),
                )
                connection.commit()
        finally:
            if cursor is not None:
                cursor.close()

            connection.close()


@patch("backend.database.file_repository.get_db_connection")
def test_connection_failure_returns_none(mock_get_connection):
    """Verify that connection failure returns None."""

    mock_get_connection.return_value = None

    result = save_file_metadata(
        "report.pdf",
        "application/pdf",
    )

    assert result is None
    mock_get_connection.assert_called_once()


@patch("backend.database.file_repository.get_db_connection")
def test_successful_insert_uses_parameterized_query(
    mock_get_connection,
):
    """Verify the SQL query and its separate parameters."""

    mock_connection = MagicMock()
    mock_cursor = MagicMock()

    mock_connection.cursor.return_value = mock_cursor
    mock_get_connection.return_value = mock_connection

    mock_cursor.lastrowid = 123

    filename = "report.pdf"
    content_type = "application/pdf"

    result = save_file_metadata(filename, content_type)

    assert result == 123

    # Verify the exact SQL query and parameters
    mock_cursor.execute.assert_called_once_with(
        "INSERT INTO files (filename,content_type) VALUES (%s, %s)",
        (filename, content_type),
    )

    mock_connection.commit.assert_called_once()
    mock_cursor.close.assert_called_once()
    mock_connection.close.assert_called_once()


@patch("backend.database.file_repository.get_db_connection")
def test_database_error_rolls_back_and_closes_resources(
    mock_get_connection,
):
    """Verify rollback and cleanup when SQL execution fails."""

    mock_connection = MagicMock()
    mock_cursor = MagicMock()

    mock_connection.cursor.return_value = mock_cursor
    mock_get_connection.return_value = mock_connection

    # Simulate a database error during SQL execution
    mock_cursor.execute.side_effect = mysql.connector.Error(
        "Simulated database error"
    )

    result = save_file_metadata(
        "report.pdf",
        "application/pdf",
    )

    assert result is None

    # Verify transaction rollback
    mock_connection.rollback.assert_called_once()

    # Verify resource cleanup
    mock_cursor.close.assert_called_once()
    mock_connection.close.assert_called_once()


# ============================================================
# Tests for delete_file_metadata()
# ============================================================


@patch("backend.database.file_repository.get_db_connection")
def test_delete_file_metadata_success(mock_get_connection):
    """Verify successful deletion of one metadata record."""

    mock_connection = MagicMock()
    mock_cursor = MagicMock()

    mock_connection.cursor.return_value = mock_cursor
    mock_get_connection.return_value = mock_connection
    mock_cursor.rowcount = 1

    result = delete_file_metadata(123)

    assert result is True

    mock_cursor.execute.assert_called_once_with(
        "DELETE FROM files WHERE id=%s",
        (123,),
    )
    mock_connection.commit.assert_called_once()
    mock_cursor.close.assert_called_once()
    mock_connection.close.assert_called_once()


@patch("backend.database.file_repository.get_db_connection")
def test_delete_file_metadata_no_matching_row(mock_get_connection):
    """Verify False is returned when no record matches."""

    mock_connection = MagicMock()
    mock_cursor = MagicMock()

    mock_connection.cursor.return_value = mock_cursor
    mock_get_connection.return_value = mock_connection
    mock_cursor.rowcount = 0

    result = delete_file_metadata(999)

    assert result is False
    mock_connection.commit.assert_not_called()
    mock_cursor.close.assert_called_once()
    mock_connection.close.assert_called_once()


@pytest.mark.parametrize(
    "file_id",
    [True, False, "123", 1.5, None, []],
)
def test_delete_file_metadata_invalid_type(file_id):
    """Verify invalid ID types raise TypeError."""

    with pytest.raises(TypeError):
        delete_file_metadata(file_id)


@pytest.mark.parametrize("file_id", [0, -1, -100])
def test_delete_file_metadata_non_positive_id(file_id):
    """Verify zero and negative IDs raise ValueError."""

    with pytest.raises(ValueError):
        delete_file_metadata(file_id)


@patch("backend.database.file_repository.get_db_connection")
def test_delete_file_metadata_connection_unavailable(
    mock_get_connection,
):
    """Verify False is returned when the database is unavailable."""

    mock_get_connection.return_value = None

    result = delete_file_metadata(123)

    assert result is False
    mock_get_connection.assert_called_once()
