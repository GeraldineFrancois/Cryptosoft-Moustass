from security.password_utils import hash_password, verify_password
from security.rsa_utils import generate_rsa_keys

def test_hash_and_verify_password():
    password = "Test123!"
    salt, hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, salt, hashed)
    assert not verify_password("wrongpass", salt, hashed)


def test_rsa_key_generation():
    public_key, private_key = generate_rsa_keys()

    assert "BEGIN PUBLIC KEY" in public_key
    assert "BEGIN PRIVATE KEY" in private_key
    assert len(private_key) > 1600  