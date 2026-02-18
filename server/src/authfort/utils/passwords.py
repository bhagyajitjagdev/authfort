"""Password hashing utilities using argon2."""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using argon2id.

    Args:
        password: The plain text password to hash.

    Returns:
        The hashed password string.
    """
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using argon2.

    Uses constant-time comparison internally (argon2-cffi handles this).

    Args:
        plain_password: The plain text password to verify.
        hashed_password: The stored password hash.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
