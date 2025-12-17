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
    elif len(args) == 2:
        full_name, email = args
        name_parts = full_name.split(' ', 1)
        firstname = name_parts[0]
        lastname = name_parts[1] if len(name_parts) > 1 else ''
    else:
        raise TypeError("create_user expects (first,last,email) or (name,email)")

    temp_password = generate_temp_password()
    salt, password_hash = hash_password(temp_password)
    public_key, private_key = generate_rsa_keys()

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO users (firstname, lastname, email, role, password_hash, password_salt, public_key, first_login)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
    """

    cursor.execute(query, (firstname, lastname, email, role, password_hash, salt, public_key))
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
        SELECT id, firstname, lastname, email, role, password_hash, password_salt, public_key, first_login
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

    # Verify password using the hashing util
    if verify_password(password, user["password_salt"], user["password_hash"]):
        return user

    return None


def login_user(email: str, password: str):
    """
    Returns user data dict if login OK, None otherwise.
    Works for any role.
    """

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, firstname, lastname, email, role, password_hash, password_salt, public_key, first_login
        FROM users
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user is None:
        return None

    # Verify password
    if verify_password(password, user["password_salt"], user["password_hash"]):
        return user

    return None

def update_password(user_id: int, new_password: str):
    salt, hashed = hash_password(new_password)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = %s, password_salt = %s, first_login = 0
        WHERE id = %s
    """, (hashed, salt, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return True
