from db.user_repository import insert_user
from db.user_repository import get_user_by_email
from services.password_services import hash_password
from services.password_services import (
    generate_salt,
    hash_password,
    generate_temporary_password
)

def admin_create_user(firstname, lastname, email, role="USER"):
    temp_password = generate_temporary_password()
    salt = generate_salt()
    password_hash = hash_password(temp_password, salt)

    insert_user(
        firstname=firstname,
        lastname=lastname,
        email=email,
        password_hash=password_hash,
        password_salt=salt,
        role=role
    )

    return temp_password  # ⚠️ À afficher UNE SEULE FOIS à l’admin

def authenticate_user(email, password):
    user = get_user_by_email(email)

    if not user:
        return None, "USER_NOT_FOUND"

    hashed = hash_password(password, user["password_salt"])

    if hashed != user["password_hash"]:
        return None, "INVALID_PASSWORD"

    if user["first_login"]:
        return user, "FIRST_LOGIN"

    return user, "SUCCESS"