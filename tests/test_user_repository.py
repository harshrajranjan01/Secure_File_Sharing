
from unittest.mock import MagicMock, patch

import mysql.connector

from backend.database.user_repository import (
    create_user,
    get_user_by_username,
)


@patch("backend.database.user_repository.get_db_connection")
def test_create_user_returns_new_id(mock_get_connection):
    connection = MagicMock()
    cursor = MagicMock()

    connection.cursor.return_value = cursor
    cursor.lastrowid = 1
    mock_get_connection.return_value = connection

    user_id = create_user("harsh", "$argon2id$example_hash")

    assert user_id == 1
    cursor.execute.assert_called_once_with(
        """
            INSERT INTO users (username, password_hash)
            VALUES (%s, %s)
        """,
        ("harsh", "$argon2id$example_hash"),
    )
    connection.commit.assert_called_once()


def test_create_user_rejects_invalid_input():
    with patch(
        "backend.database.user_repository.get_db_connection"
    ) as mock_get_connection:
        assert create_user("", "$argon2id$example_hash") is None
        assert create_user("harsh", "") is None
        assert create_user(None, "$argon2id$example_hash") is None
        assert create_user("harsh", None) is None

        # Invalid input must not access the database.
        mock_get_connection.assert_not_called()


@patch("backend.database.user_repository.get_db_connection")
def test_duplicate_username_does_not_expose_mysql_error(
    mock_get_connection,
):
    connection = MagicMock()
    cursor = MagicMock()

    connection.cursor.return_value = cursor
    mock_get_connection.return_value = connection

    cursor.execute.side_effect = mysql.connector.IntegrityError(
        msg="Duplicate entry 'harsh' for key 'username'"
    )

    result = create_user("harsh", "$argon2id$example_hash")

    assert result is None
    connection.rollback.assert_called_once()

    # The function returns None, not the database exception.
    connection.close.assert_called_once()
    cursor.close.assert_called_once()


@patch("backend.database.user_repository.get_db_connection")
def test_get_user_by_username_returns_record(mock_get_connection):
    connection = MagicMock()
    cursor = MagicMock()

    expected_user = {
        "id": 1,
        "username": "harsh",
        "password_hash": "$argon2id$example_hash",
    }

    cursor.fetchone.return_value = expected_user
    connection.cursor.return_value = cursor
    mock_get_connection.return_value = connection

    result = get_user_by_username("harsh")

    assert result == expected_user
    cursor.execute.assert_called_once_with(
        """
            SELECT id, username, password_hash
            FROM users
            WHERE username = %s
        """,
        ("harsh",),
    )


@patch("backend.database.user_repository.get_db_connection")
def test_get_user_by_username_returns_none_when_unknown(
    mock_get_connection,
):
    connection = MagicMock()
    cursor = MagicMock()

    cursor.fetchone.return_value = None
    connection.cursor.return_value = cursor
    mock_get_connection.return_value = connection

    assert get_user_by_username("unknown_user") is None


@patch("backend.database.user_repository.get_db_connection")
def test_create_user_closes_resources(mock_get_connection):
    connection = MagicMock()
    cursor = MagicMock()

    connection.cursor.return_value = cursor
    cursor.lastrowid = 5
    mock_get_connection.return_value = connection

    create_user("harsh", "$argon2id$example_hash")

    cursor.close.assert_called_once()
    connection.close.assert_called_once()


@patch("backend.database.user_repository.get_db_connection")
def test_get_user_closes_resources(mock_get_connection):
    connection = MagicMock()
    cursor = MagicMock()

    cursor.fetchone.return_value = None
    connection.cursor.return_value = cursor
    mock_get_connection.return_value = connection

    get_user_by_username("harsh")

    cursor.close.assert_called_once()
    connection.close.assert_called_once()


@patch("backend.database.user_repository.get_db_connection")
def test_create_user_rolls_back_on_database_error(
    mock_get_connection,
):
    connection = MagicMock()
    cursor = MagicMock()

    connection.cursor.return_value = cursor
    mock_get_connection.return_value = connection

    cursor.execute.side_effect = mysql.connector.Error(
        msg="Database unavailable"
    )

    result = create_user("harsh", "$argon2id$example_hash")

    assert result is None
    connection.rollback.assert_called_once()
    cursor.close.assert_called_once()
    connection.close.assert_called_once()
