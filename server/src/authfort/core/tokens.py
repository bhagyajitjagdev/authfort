"""JWT access token creation and verification."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt

from authfort.config import AuthFortConfig


def create_access_token(
    user_id: uuid.UUID,
    email: str,
    roles: list[str],
    token_version: int,
    kid: str,
    private_key: str,
    config: AuthFortConfig,
    name: str | None = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        user_id: The user's UUID.
        email: The user's email.
        roles: List of role strings.
        token_version: Current token version (for immediate invalidation).
        kid: Key ID of the signing key.
        private_key: PEM-encoded private key for signing.
        config: AuthFort configuration.
        name: Optional display name.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "email": email,
        "name": name,
        "roles": roles,
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(seconds=config.access_token_expire_seconds),
        "iss": config.jwt_issuer,
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm=config.jwt_algorithm,
        headers={"kid": kid},
    )


def verify_access_token(token: str, public_key: str, config: AuthFortConfig) -> dict:
    """Verify and decode a JWT access token.

    Args:
        token: The encoded JWT string.
        public_key: PEM-encoded public key for verification.
        config: AuthFort configuration.

    Returns:
        Decoded payload dict.

    Raises:
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the token is invalid.
    """
    return jwt.decode(
        token,
        public_key,
        algorithms=[config.jwt_algorithm],
        issuer=config.jwt_issuer,
        options={"require": ["sub", "email", "roles", "ver", "exp", "iat", "iss"]},
    )


def get_unverified_header(token: str) -> dict:
    """Get the JWT header without verifying the signature.

    Used to extract the `kid` to look up the correct public key.

    Args:
        token: The encoded JWT string.

    Returns:
        Header dict containing 'kid', 'alg', etc.
    """
    return jwt.get_unverified_header(token)
