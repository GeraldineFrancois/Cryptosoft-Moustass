from db.database import get_connection
from security.password_utils import hash_password
from security.rsa_utils import generate_rsa_keys

def create_user(firstname, lastname, email, default_password="Temp123!"):
    salt, password_hash = hash_password(default_password)
    public_key, private_key = generate_rsa_keys()

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO users (firstname, lastname, email, password_hash, salt, public_key, private_key)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, (firstname, lastname, email, password_hash, salt, public_key, private_key))
    conn.commit()

    cursor.close()
    conn.close()

    return True
