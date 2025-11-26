import hashlib
import os
import hmac

def hash_password(password: str):
    """
    Generates a random salt and returns (salt, hashed_password)
    """
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',                  
        password.encode(),         
        salt,                      
        100000        
    )
    return salt.hex(), hashed_password.hex()


def verify_password(password: str, salt: str, stored_hash: str):
    """
    Verifies a password using the stored salt and hash.
    """
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        bytes.fromhex(salt),
        100000
    )

    # Secure comparison to avoid timing attacks
    return hmac.compare_digest(new_hash.hex(), stored_hash)
