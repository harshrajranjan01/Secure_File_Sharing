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
