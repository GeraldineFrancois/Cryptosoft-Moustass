import hashlib
import os
import hmac

def hash_password(password: str) -> str:
    """
    Generates a random salt and returns the combined "salt:hashed_password" string for storage.
    """
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',                  
        password.encode(),         
        salt,                      
        100000        
    )
    return f"{salt.hex()}:{hashed_password.hex()}"


def verify_password(password: str, stored_combined: str) -> bool:
    """
    Verifies a password using the stored combined salt:hash string.
    """
    try:
        salt_hex, stored_hash = stored_combined.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        # Secure comparison to avoid timing attacks
        return hmac.compare_digest(new_hash.hex(), stored_hash)
    except ValueError:
        return False
