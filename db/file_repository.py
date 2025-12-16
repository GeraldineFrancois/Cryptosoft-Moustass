from db.connection import get_connection

def insert_code_file(file_name, file_hash, user_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO code_files (file_name, file_hash, user_id)
        VALUES (%s, %s, %s)
    """, (file_name, file_hash, user_id))

    conn.commit()
    cursor.close()
    conn.close()


def insert_signature(signature_value, file_id, user_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO signatures (signature_value, file_id, user_id)
        VALUES (%s, %s, %s)
    """, (signature_value, file_id, user_id))

    conn.commit()
    cursor.close()
    conn.close()
