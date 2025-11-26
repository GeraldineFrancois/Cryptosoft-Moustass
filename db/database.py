import mysql.connector
import os

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME", "cryptosoft_moustass")
    )

def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result


def insert_user(firstname, lastname, email, password_hash, salt, pk, sk):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO users (firstname, lastname, email, password_hash, salt, first_login, public_key, private_key)
        VALUES (%s, %s, %s, %s, %s, TRUE, %s, %s)
    """

    cursor.execute(query, (firstname, lastname, email, password_hash, salt, pk, sk))
    conn.commit()

    cursor.close()
    conn.close()
