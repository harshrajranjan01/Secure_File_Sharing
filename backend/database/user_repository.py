
import mysql.connector
from mysql.connector import IntegrityError

from backend.database.connection import get_db_connection


class DuplicateUsernameError(Exception):
    """Raised when a username already exists."""


def create_user(username: str, password_hash: str) -> int | None:
    """Create a user and return their ID, or None if creation fails."""

    if not isinstance(username, str) or not username.strip():
        return None

    if not isinstance(password_hash, str) or not password_hash:
        return None

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        if connection is None:
            return None

        cursor = connection.cursor()

        query = """
            INSERT INTO users (username, password_hash)
            VALUES (%s, %s)
        """

        values = (username.strip(), password_hash)

        cursor.execute(query, values)

        user_id = cursor.lastrowid

        connection.commit()

        return user_id

    except IntegrityError as exc:
        if connection is not None:
            try:
                connection.rollback()
            except mysql.connector.Error:
                pass

        # MySQL error 1062 indicates a duplicate-key violation.
        if exc.errno == 1062:
            raise DuplicateUsernameError(
                "Username already exists."
            ) from exc

        return None

    except mysql.connector.Error:
        if connection is not None:
            try:
                connection.rollback()
            except mysql.connector.Error:
                pass

        return None

    finally:
        if cursor is not None:
            try:
                cursor.close()
            except mysql.connector.Error:
                pass

        if connection is not None:
            try:
                connection.close()
            except mysql.connector.Error:
                pass


def get_user_by_username(username: str) -> dict | None:
    """Retrieve a user for authentication, or None if not found."""

    if not isinstance(username, str) or not username.strip():
        return None

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        if connection is None:
            return None

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = %s
        """

        cursor.execute(query, (username.strip(),))

        return cursor.fetchone()

    except mysql.connector.Error:
        return None

    finally:
        if cursor is not None:
            try:
                cursor.close()
            except mysql.connector.Error:
                pass

        if connection is not None:
            try:
                connection.close()
            except mysql.connector.Error:
                pass
