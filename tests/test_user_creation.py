import time
from services.user_service import create_user
from db.database import get_user_by_email

def test_create_user():
    email = f"test_user_{int(time.time())}@example.com"

    temp_password, public_key, private_key = create_user("John", "Doe", email)

    assert temp_password is not None
    assert len(temp_password) >= 12
    assert public_key is not None
    assert private_key is not None

    user = get_user_by_email(email)

    assert user is not None
    assert user["email"] == email
    assert user["firstname"] == "John"
    assert user["lastname"] == "Doe"
    assert user["public_key"] is not None
    assert user["password_hash"] is not None
    assert user["password_salt"] is not None
