import time
from services.user_service import create_user, login_user, update_password
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


def test_login_user():
    email = f"test_login_{int(time.time())}@example.com"

    temp_password, _, _ = create_user("Jane", "Smith", email)

    # Test successful login
    user = login_user(email, temp_password)
    assert user is not None
    assert user["email"] == email

    # Test failed login with wrong password
    user_wrong = login_user(email, "wrongpassword")
    assert user_wrong is None

    # Test login with non-existent email
    user_none = login_user("nonexistent@example.com", temp_password)
    assert user_none is None


def test_update_password():
    email = f"test_update_{int(time.time())}@example.com"

    temp_password, _, _ = create_user("Alice", "Wonder", email)

    user = get_user_by_email(email)
    assert user["first_login"] == 1

    # Update password
    new_password = "NewSecurePass123!"
    update_password(user["id"], new_password)

    # Check that first_login is now 0
    updated_user = get_user_by_email(email)
    assert updated_user["first_login"] == 0

    # Check that login with old password fails
    old_login = login_user(email, temp_password)
    assert old_login is None

    # Check that login with new password succeeds
    new_login = login_user(email, new_password)
    assert new_login is not None
    assert new_login["email"] == email
