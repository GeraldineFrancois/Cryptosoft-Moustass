from db.connection import get_connection

def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, firstname, lastname, email, role,
               password_hash, password_salt,
               public_key, first_login
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def insert_user(firstname, lastname, email, password_hash, password_salt, role="USER"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (
            firstname, lastname, email, role,
            password_hash, password_salt,
            first_login, public_key
        )
        VALUES (%s, %s, %s, %s, %s, %s, TRUE, NULL)
    """, (firstname, lastname, email, role, password_hash, password_salt))

    conn.commit()
    cursor.close()
    conn.close()

def update_user_password(user_id, password_hash, password_salt):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = %s,
            password_salt = %s,
            first_login = FALSE
        WHERE id = %s
    """, (password_hash, password_salt, user_id))

    conn.commit()
    cursor.close()
    conn.close()

