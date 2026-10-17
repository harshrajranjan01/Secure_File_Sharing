from backend.database.connection import get_db_connection

def test_database_connection():
    connection=None
    cursor=None

    try:
        connection=get_db_connection()

        assert connection is not None, "Database connnection failed"

        assert connection.is_connected() is True

        cursor=connection.cursor()

        cursor.execute("SELECT DATABASE()")
        result=cursor.fetchone()

        assert result[0]=="secure_file_sharing"

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()