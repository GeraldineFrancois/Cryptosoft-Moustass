import secrets
import string
from db.database import get_connection
from security.password_utils import hash_password, verify_password
from security.rsa_utils import generate_rsa_keys

# standardized DB connection error message
DB_CONN_ERR = "Database connection failed: check DB credentials (DB_PASSWORD / DB_PASSWORD_FILE)."



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
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
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
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
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
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
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
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
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


# -------------------- FILE UPLOAD ---------------------

def upload_file(user_id: int, file_path: str):
    """
    Upload a source code file: compute SHA256 hash and store in DB.
    """
    import hashlib
    import os

    if not os.path.isfile(file_path):
        raise ValueError("File does not exist or is not a file.")

    # Compute SHA256 hash
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    file_name = os.path.basename(file_path)

    conn = get_connection()
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO code_files (file_name, file_hash, user_id)
        VALUES (%s, %s, %s)
    """, (file_name, file_hash, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return file_name, file_hash


# -------------------- FILE SIGNATURE ---------------------

def sign_file(admin_id: int, file_id: int, private_key_pem: str):
    """
    Sign a code file using admin's private RSA key.
    Only admins can sign files.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    import base64

    # Check if user is admin
    conn = get_connection()
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT role FROM users WHERE id = %s", (admin_id,))
    user = cursor.fetchone()
    if not user or user['role'] != 'ADMIN':
        cursor.close()
        conn.close()
        raise ValueError("Only admins can sign files.")

    # Get file hash
    cursor.execute("SELECT file_hash FROM code_files WHERE id = %s", (file_id,))
    file_row = cursor.fetchone()
    if not file_row:
        cursor.close()
        conn.close()
        raise ValueError("File not found.")

    file_hash = file_row['file_hash']

    # Load private key
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
    except Exception as e:
        cursor.close()
        conn.close()
        raise ValueError(f"Invalid private key: {str(e)}")

    # Sign the hash
    signature = private_key.sign(
        bytes.fromhex(file_hash),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode()

    # Insert signature
    cursor.execute("""
        INSERT INTO signatures (signature_value, file_id, user_id)
        VALUES (%s, %s, %s)
    """, (signature_b64, file_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    return signature_b64


def verify_file_signature(file_id: int):
    """
    Verify the signature of a file using the admin's public key.
    Returns True if valid, False otherwise.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    import base64

    conn = get_connection()
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
    cursor = conn.cursor(dictionary=True)

    # Get file hash and signature
    cursor.execute("""
        SELECT cf.file_hash, s.signature_value, u.public_key
        FROM code_files cf
        JOIN signatures s ON cf.id = s.file_id
        JOIN users u ON s.user_id = u.id
        WHERE cf.id = %s
    """, (file_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        raise ValueError("No signature found for this file.")

    file_hash = row['file_hash']
    signature_b64 = row['signature_value']
    public_key_pem = row['public_key']

    # Load public key
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception as e:
        raise ValueError(f"Invalid public key: {str(e)}")

    # Decode signature
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False

    # Verify
    try:
        public_key.verify(
            signature,
            bytes.fromhex(file_hash),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_uploaded_files():
    """
    Get list of all uploaded files with user info.
    """
    conn = get_connection()
    if conn is None:
        raise RuntimeError(DB_CONN_ERR)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT cf.id, cf.file_name, cf.file_hash, cf.file_date_created,
               u.firstname, u.lastname, u.email
        FROM code_files cf
        JOIN users u ON cf.user_id = u.id
        ORDER BY cf.file_date_created DESC
    """)
    files = cursor.fetchall()
    cursor.close()
    conn.close()
    return files
