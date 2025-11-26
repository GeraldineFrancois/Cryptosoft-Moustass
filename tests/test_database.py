import os
from db.database import get_connection, get_user_by_email

def test_connection():
    conn = get_connection()
    assert conn.is_connected()
    conn.close()


def test_user_not_found():
    user = get_user_by_email("doesnotexist@example.com")
    assert user is None
