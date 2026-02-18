"""Test fixtures for authfort-service tests.

All tests are DB-free — they generate RSA keys, create JWTs manually,
and mock JWKS responses using httpx MockTransport.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

pytestmark = pytest.mark.asyncio


@pytest.fixture
def rsa_key_pair():
    """Generate a test RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


@pytest.fixture
def test_kid():
    return f"test-key-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def jwk_from_public_key(rsa_key_pair, test_kid):
    """Convert the test public key to JWK format."""
    import base64

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    _, public_pem = rsa_key_pair
    public_key = load_pem_public_key(public_pem.encode("utf-8"))
    public_numbers = public_key.public_numbers()

    def _int_to_b64url(value: int) -> str:
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder="big")
        return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA",
        "kid": test_kid,
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64url(public_numbers.n),
        "e": _int_to_b64url(public_numbers.e),
    }


@pytest.fixture
def jwks_response(jwk_from_public_key):
    """A JWKS response body with one key."""
    return {"keys": [jwk_from_public_key]}


def create_test_token(
    private_key_pem: str,
    kid: str,
    *,
    user_id: str | None = None,
    email: str = "test@example.com",
    roles: list[str] | None = None,
    token_version: int = 1,
    issuer: str = "authfort",
    expires_in: int = 900,
) -> str:
    """Create a test JWT signed with the given private key."""
    now = datetime.now(UTC)
    payload = {
        "sub": user_id or str(uuid.uuid4()),
        "email": email,
        "name": "Test User",
        "roles": roles or [],
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "iss": issuer,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": kid})
