import os
import mysql.connector
from mysql.connector import Error


def get_connection():
    """
    Establish secure connection to MySQL using environment variables.
    """

    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "moustass_db")
        )

        if conn.is_connected():
            return conn

    except Error as e:
        print(f"[DATABASE ERROR] {e}")
        return None


def get_user_by_email(email: str):
    """
    Returns a dict with user info if found, otherwise None.
    """
    conn = get_connection()
    if conn is None:
        return None

    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT idusers, name, email, role, password_hash, salt, public_key, private_key, is_first_password
        FROM users
        WHERE email = %s
    """

    cursor.execute(query, (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return user


def insert_log_auth(user_id: int, auth_attempt: int):
    """
    Insert authentication logs into log_auth table.
    """
    conn = get_connection()
    if conn is None:
        return False

    cursor = conn.cursor()

    query = """
        INSERT INTO log_auth (iduser, log_date, log_time, auth_attempt)
        VALUES (%s, CURRENT_DATE(), NOW(), %s)
    """

    cursor.execute(query, (user_id, auth_attempt))
    conn.commit()

    cursor.close()
    conn.close()
    return True


def insert_log_file(user_id: int, public_key: str, file_hash: str, signed_hash: str):
    """
    Insert file signatures in log_file table.
    """
    conn = get_connection()
    if conn is None:
        return False

    cursor = conn.cursor()

    query = """
        INSERT INTO log_file (id_user, log_journal, user_public_key, user_file_hash, signed_filed_hash)
        VALUES (%s, NOW(), %s, %s, %s)
    """

    cursor.execute(query, (user_id, public_key, file_hash, signed_hash))
    conn.commit()

    cursor.close()
    conn.close()
    return True
