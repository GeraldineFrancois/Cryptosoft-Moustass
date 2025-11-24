import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="MyStrongP@ss123!",
        database="cryptosoft_moustass"
    )

def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result
