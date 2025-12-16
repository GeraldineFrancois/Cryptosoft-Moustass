from db.connection import get_connection

def insert_user_log(action_type, file_name, file_hash,
                    signature_value, public_key, success, user_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users_logs (
            action_type, file_name, file_hash,
            signature_value, public_key, success, user_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (action_type, file_name, file_hash,
          signature_value, public_key, success, user_id))

    conn.commit()
    cursor.close()
    conn.close()


def get_user_logs(user_id, is_admin=False):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if is_admin:
        cursor.execute("""
            SELECT * FROM users_logs
            ORDER BY log_date DESC
            LIMIT 1000
        """)
    else:
        cursor.execute("""
            SELECT * FROM users_logs
            WHERE user_id = %s
            ORDER BY log_date DESC
        """, (user_id,))

    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return logs
