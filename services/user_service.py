import secrets
import string
from db.database import get_connection
from security.password_utils import hash_password, verify_password
from security.rsa_utils import generate_rsa_keys



def generate_temp_password(length=12):
    """
    Generates a secure temporary password for new users.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# -------------------- USER CREATION ---------------------

def create_user(*args, role: str = "USER"):
    """
    Create a standard user with:
    - generated RSA keys
    - temporary password
    - is_first_password = TRUE
    """

    # Support two call signatures:
    # - create_user(firstname, lastname, email)
    # - create_user(full_name, email)
    if len(args) == 3:
        firstname, lastname, email = args
        name = f"{firstname} {lastname}".strip()
    elif len(args) == 2:
        name, email = args
    else:
        raise TypeError("create_user expects (first,last,email) or (name,email)")

    temp_password = generate_temp_password()
    salt, password_hash = hash_password(temp_password)
    public_key, private_key = generate_rsa_keys()

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO users (name, email, role, password_hash, salt, public_key, private_key, is_first_password)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
    """

    cursor.execute(query, (name, email, role, password_hash, salt, public_key, private_key))
    conn.commit()

    cursor.close()
    conn.close()

    return temp_password, public_key, private_key


def create_admin(name: str, email: str):
    """
    Admin creation uses the same logic as create_user() but role='ADMIN'
    """
    return create_user(name, email, role="ADMIN")


# -------------------- LOGIN LOGIC ---------------------

def login_admin(email: str, password: str):
    """
    Returns:
      - user data dict if login OK AND role='ADMIN'
      - None otherwise
    """

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT idusers, name, email, role, password_hash, salt, public_key, private_key, is_first_password
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user is None:
        return None

    if user["role"] != "ADMIN":
        return None

    # Verify password using the hashing util (use stored salt)
    stored_salt = user.get("salt")
    if stored_salt is None:
        return None

    if verify_password(password, stored_salt, user["password_hash"]):
        return user

    return None


# -------------------- PASSWORD RESET ---------------------

def update_password(user_id: int, new_password: str):
    salt, hashed = hash_password(new_password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = %s, salt = %s, is_first_password = 0
        WHERE idusers = %s
    """, (hashed, salt, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return True
