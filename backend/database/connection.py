
import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Return a connected MySQL connection, or None on failure."""

    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            connection_timeout=5,
        )

        if connection.is_connected():
            return connection

        connection.close()
        print("Database connection was not established.")
        return None

    except (mysql.connector.Error, ValueError):
        print("Database connection failed.")
        return None
