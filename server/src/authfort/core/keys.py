"""RSA key pair generation and JWKS utilities."""

import uuid
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair() -> tuple[str, str]:
    """Generate an RSA 2048-bit key pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def generate_kid() -> str:
    """Generate a unique key ID for JWKS.

    Format: key-YYYY-MM-uuid_short
    """
    now = datetime.now(UTC)
    short_id = uuid.uuid4().hex[:8]
    return f"key-{now.year}-{now.month:02d}-{short_id}"


def public_key_to_jwk(kid: str, public_key_pem: str, algorithm: str = "RS256") -> dict:
    """Convert a PEM public key to JWK format for the JWKS endpoint.

    Args:
        kid: The key ID.
        public_key_pem: PEM-encoded public key string.
        algorithm: The signing algorithm (default RS256).

    Returns:
        JWK dict with kty, kid, use, alg, n, e fields.
    """
    import base64

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    public_numbers = public_key.public_numbers()

    def _int_to_base64url(value: int) -> str:
        """Convert an integer to a base64url-encoded string."""
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder="big")
        return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": algorithm,
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
    }
