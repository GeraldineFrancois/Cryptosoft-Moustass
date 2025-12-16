import os
import hashlib
import secrets

def generate_salt():
    return secrets.token_hex(32)

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_temporary_password():
    return secrets.token_urlsafe(10)
