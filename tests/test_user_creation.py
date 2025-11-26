from services.user_service import create_user
from db.database import get_user_by_email

def test_create_user():
    email = "test_user@example.com"

    create_user("John", "Doe", email)

    user = get_user_by_email(email)

    assert user is not None
    assert user["email"] == email
    assert user["public_key"] is not None
    assert user["private_key"] is not None
    assert user["password_hash"] is not None
    assert user["salt"] is not None
