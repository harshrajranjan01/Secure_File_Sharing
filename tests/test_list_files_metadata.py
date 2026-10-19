import unittest
from unittest.mock import MagicMock, patch

import mysql.connector

from backend.database.file_repository import list_files_metadata


class TestListFilesMetadata(unittest.TestCase):

    @patch("backend.database.file_repository.get_db_connection")
    def test_returns_file_metadata(self, mock_get_connection):
        """Return file metadata as a list of dictionaries."""

        mock_connection = MagicMock()
        mock_cursor = MagicMock()

        mock_get_connection.return_value = mock_connection
        mock_connection.cursor.return_value = mock_cursor

        expected_data = [
            {
                "id": 2,
                "filename": "report.pdf",
                "content_type": "application/pdf",
                "created_at": "2026-10-19 12:00:00",
                "size_bytes": 2048,
            },
            {
                "id": 1,
                "filename": "notes.pdf",
                "content_type": "application/pdf",
                "created_at": "2026-10-18 12:00:00",
                "size_bytes": 1024,
            },
        ]

        mock_cursor.fetchall.return_value = expected_data

        result = list_files_metadata()

        self.assertEqual(result, expected_data)
        mock_connection.cursor.assert_called_once_with(dictionary=True)
        mock_cursor.execute.assert_called_once()

        query = mock_cursor.execute.call_args[0][0]
        self.assertIn("SELECT id, filename, content_type, created_at, size_bytes", query)
        self.assertIn("ORDER BY created_at DESC, id DESC", query)

        mock_cursor.close.assert_called_once()
        mock_connection.close.assert_called_once()

    @patch("backend.database.file_repository.get_db_connection")
    def test_returns_empty_list_when_connection_unavailable(
        self, mock_get_connection
    ):
        """Return an empty list if the database connection is unavailable."""

        mock_get_connection.return_value = None

        result = list_files_metadata()

        self.assertEqual(result, [])

    @patch("backend.database.file_repository.get_db_connection")
    def test_returns_empty_list_when_database_error_occurs(
        self, mock_get_connection
    ):
        """Return an empty list when executing the query fails."""

        mock_connection = MagicMock()
        mock_cursor = MagicMock()

        mock_get_connection.return_value = mock_connection
        mock_connection.cursor.return_value = mock_cursor

        mock_cursor.execute.side_effect = mysql.connector.Error(
            "Database query failed"
        )

        result = list_files_metadata()

        self.assertEqual(result, [])
        mock_cursor.close.assert_called_once()
        mock_connection.close.assert_called_once()

    @patch("backend.database.file_repository.get_db_connection")
    def test_returns_empty_list_when_no_files_exist(self, mock_get_connection):
        """Return an empty list when the table has no records."""

        mock_connection = MagicMock()
        mock_cursor = MagicMock()

        mock_get_connection.return_value = mock_connection
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []

        result = list_files_metadata()

        self.assertEqual(result, [])

    @patch("backend.database.file_repository.get_db_connection")
    def test_closes_resources_after_success(self, mock_get_connection):
        """Close the cursor and connection after a successful query."""

        mock_connection = MagicMock()
        mock_cursor = MagicMock()

        mock_get_connection.return_value = mock_connection
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []

        list_files_metadata()

        mock_cursor.close.assert_called_once()
        mock_connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()