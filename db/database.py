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

    cursor.execute(
        "SELECT id, firstname, lastname, email, role, password_hash, password_salt, public_key, first_login FROM users WHERE email=%s",
        (email,)
    )
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result


def insert_user(firstname, lastname, email, password_hash, password_salt, role='USER'):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO users (firstname, lastname, email, role, password_hash, password_salt, first_login, public_key)
        VALUES (%s, %s, %s, %s, %s, %s, TRUE, NULL)
    """

    cursor.execute(query, (firstname, lastname, email, role, password_hash, password_salt))
    conn.commit()

    cursor.close()
    conn.close()

def insert_code_file(file_name, file_hash, user_id):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO code_files (file_name, file_hash, user_id)
        VALUES (%s, %s, %s)
    """
    cursor.execute(query, (file_name, file_hash, user_id))
    conn.commit()
    cursor.close()
    conn.close()

def insert_signature(signature_value, file_id, user_id):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO signatures (signature_value, file_id, user_id)
        VALUES (%s, %s, %s)
    """
    cursor.execute(query, (signature_value, file_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()

def insert_user_log(action_type, file_name, file_hash, signature_value, public_key, success, user_id):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO users_logs (action_type, file_name, file_hash, signature_value, public_key, success, user_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(query, (action_type, file_name, file_hash, signature_value, public_key, success, user_id))
    conn.commit()
    cursor.close()
    conn.close()

def get_user_logs(user_id, is_admin=False):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if is_admin:
        cursor.execute("SELECT * FROM users_logs ORDER BY log_date DESC LIMIT 1000")
    else:
        cursor.execute("SELECT * FROM users_logs WHERE user_id=%s ORDER BY log_date DESC", (user_id,))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results
