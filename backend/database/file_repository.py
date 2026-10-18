import mysql.connector

from backend.database.connection import get_db_connection


def save_file_metadata(filename, content_type):

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        if connection is None:
            return None

        cursor = connection.cursor()

        query = "INSERT INTO files (filename,content_type) VALUES (%s, %s)"
        values = (filename, content_type)

        cursor.execute(query, values)

        file_id = cursor.lastrowid

        connection.commit()

        return file_id

    except mysql.connector.Error:
        # Roll back the transaction if a database error occurs
        if connection is not None:
            try:
                connection.rollback()
            except mysql.connector.Error:
                pass

        # Do not expose internal database details
        return None

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


def _is_valid_encrypted_file_metadata(
    filename: str,
    content_type: str,
    storage_key: str,
    file_nonce: bytes,
    wrapped_dek: bytes,
    key_nonce: bytes,
    size_bytes: int,
) -> bool:
    """Validate metadata before storing it in the database."""

    if not isinstance(filename, str) or not filename.strip():
        return False

    if not isinstance(content_type, str) or not content_type.strip():
        return False

    if (
        not isinstance(storage_key, str)
        or len(storage_key) != 64
        or any(char not in "0123456789abcdef" for char in storage_key)
    ):
        return False

    if not isinstance(file_nonce, bytes) or len(file_nonce) != 12:
        return False

    if not isinstance(key_nonce, bytes) or len(key_nonce) != 12:
        return False

    if not isinstance(wrapped_dek, bytes) or len(wrapped_dek) != 48:
        return False

    # bool is a subclass of int, so reject it explicitly.
    if type(size_bytes) is not int or not 1 <= size_bytes <= 10 * 1024 * 1024:
        return False

    return True


def save_encrypted_file_metadata(
        filename: str,
        content_type: str,
        storage_key: str,
        file_nonce: bytes,
        wrapped_dek: bytes,
        key_nonce: bytes,  # Nonce used to wrap the DEK
        size_bytes: int,
) -> int | None:

    # Reject invalid data before accessing MySQL.
    if not _is_valid_encrypted_file_metadata(
        filename,
        content_type,
        storage_key,
        file_nonce,
        wrapped_dek,
        key_nonce,
        size_bytes,
    ):
        return None

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        if connection is None:
            return None

        cursor = connection.cursor()

        query = """
                INSERT INTO files (
                    filename,
                    content_type,
                    storage_key,
                    file_nonce,
                    wrapped_dek,
                    key_nonce,
                    size_bytes
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

        values = (
            filename,
            content_type,
            storage_key,
            file_nonce,
            wrapped_dek,
            key_nonce,
            size_bytes
        )
        cursor.execute(query, values)

        file_id = cursor.lastrowid

        connection.commit()

        return file_id

    except mysql.connector.Error:
        # Roll back if a database operation fails.
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
