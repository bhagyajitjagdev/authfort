"""Refresh token utilities — generation and hashing."""

import hashlib
import secrets


def generate_refresh_token() -> tuple[str, str]:
    """Generate a cryptographically secure refresh token.

    Returns:
        Tuple of (raw_token, token_hash).
        - raw_token: sent to the client (never stored in DB)
        - token_hash: SHA-256 hash stored in the database
    """
    raw_token = secrets.token_urlsafe(64)
    token_hash = hash_refresh_token(raw_token)
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Hash a refresh token using SHA-256.

    Args:
        raw_token: The raw opaque token string.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
