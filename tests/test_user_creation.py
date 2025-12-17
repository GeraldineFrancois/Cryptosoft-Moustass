import time
from services.user_service import create_user, login_user, update_password, upload_file
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


def test_upload_file():
    import tempfile
    import os

    email = f"test_upload_{int(time.time())}@example.com"
    temp_password, _, _ = create_user("Bob", "Builder", email)
    user = login_user(email, temp_password)

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("# Test Python file\nprint('Hello World')\n")
        temp_file_path = f.name

    try:
        # Upload the file
        file_name, file_hash = upload_file(user["id"], temp_file_path)

        assert file_name == os.path.basename(temp_file_path)
        assert len(file_hash) == 64  # SHA256 hex length

        # Verify the hash
        import hashlib
        sha256 = hashlib.sha256()
        with open(temp_file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        expected_hash = sha256.hexdigest()
        assert file_hash == expected_hash

    finally:
        os.unlink(temp_file_path)
