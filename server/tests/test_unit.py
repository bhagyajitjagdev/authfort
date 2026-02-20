"""Unit tests for pure functions — no database needed."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from authfort.config import AuthFortConfig
from authfort.core.keys import generate_key_pair, generate_kid, public_key_to_jwk
from authfort.core.refresh import generate_refresh_token, hash_refresh_token
from authfort.core.tokens import (
    create_access_token,
    get_unverified_header,
    verify_access_token,
)
from authfort.utils.passwords import hash_password, verify_password

# Test config for JWT tests
_test_config = AuthFortConfig(database_url="postgresql+asyncpg://test:test@localhost/test")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_produces_argon2_string(self):
        hashed = hash_password("mysecretpassword")
        assert hashed.startswith("$argon2")

    def test_verify_correct_password(self):
        hashed = hash_password("correcthorse")
        assert verify_password("correcthorse", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("correcthorse")
        assert verify_password("wronghorse", hashed) is False

    def test_different_passwords_produce_different_hashes(self):
        h1 = hash_password("password1")
        h2 = hash_password("password2")
        assert h1 != h2

    def test_same_password_produces_different_hashes(self):
        """Argon2 uses random salt, so same input -> different hash."""
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Refresh token generation
# ---------------------------------------------------------------------------


class TestRefreshToken:
    def test_generate_produces_tuple(self):
        raw, hashed = generate_refresh_token()
        assert isinstance(raw, str)
        assert isinstance(hashed, str)
        assert len(raw) > 32  # url-safe base64 of 64 bytes
        assert len(hashed) == 64  # SHA-256 hex digest

    def test_hash_is_deterministic(self):
        raw = "test_token_value"
        h1 = hash_refresh_token(raw)
        h2 = hash_refresh_token(raw)
        assert h1 == h2

    def test_hash_matches_generated(self):
        raw, hashed = generate_refresh_token()
        assert hash_refresh_token(raw) == hashed

    def test_different_tokens_different_hashes(self):
        raw1, hash1 = generate_refresh_token()
        raw2, hash2 = generate_refresh_token()
        assert raw1 != raw2
        assert hash1 != hash2


# ---------------------------------------------------------------------------
# RSA key generation
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    def test_generate_key_pair_returns_pem_strings(self):
        private_pem, public_pem = generate_key_pair()
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem

    def test_generate_kid_format(self):
        kid = generate_kid()
        assert kid.startswith("key-")
        # Format: key-YYYY-MM-xxxxxxxx
        parts = kid.split("-")
        assert len(parts) == 4
        assert len(parts[3]) == 8  # 8 hex chars

    def test_public_key_to_jwk(self):
        _, public_pem = generate_key_pair()
        kid = "test-kid-001"
        jwk = public_key_to_jwk(kid, public_pem)

        assert jwk["kty"] == "RSA"
        assert jwk["kid"] == kid
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "n" in jwk  # modulus
        assert "e" in jwk  # exponent


# ---------------------------------------------------------------------------
# JWT creation and verification
# ---------------------------------------------------------------------------


class TestJWT:
    @pytest.fixture(autouse=True)
    def setup_keys(self):
        """Generate a key pair for all JWT tests."""
        self.private_pem, self.public_pem = generate_key_pair()
        self.kid = "test-kid"
        self.user_id = uuid.uuid4()

    def test_create_and_verify_token(self):
        token = create_access_token(
            user_id=self.user_id,
            email="test@example.com",
            roles=["user"],
            token_version=0,
            kid=self.kid,
            private_key=self.private_pem,
            config=_test_config,
            name="Test User",
        )

        payload = verify_access_token(token, self.public_pem, _test_config)

        assert payload["sub"] == str(self.user_id)
        assert payload["email"] == "test@example.com"
        assert payload["roles"] == ["user"]
        assert payload["ver"] == 0
        assert payload["name"] == "Test User"
        assert payload["iss"] == _test_config.jwt_issuer

    def test_token_has_kid_in_header(self):
        token = create_access_token(
            user_id=self.user_id,
            email="test@example.com",
            roles=[],
            token_version=0,
            kid=self.kid,
            private_key=self.private_pem,
            config=_test_config,
        )

        header = get_unverified_header(token)
        assert header["kid"] == self.kid
        assert header["alg"] == "RS256"

    def test_verify_with_wrong_key_fails(self):
        token = create_access_token(
            user_id=self.user_id,
            email="test@example.com",
            roles=[],
            token_version=0,
            kid=self.kid,
            private_key=self.private_pem,
            config=_test_config,
        )

        # Generate a different key pair
        _, other_public = generate_key_pair()

        with pytest.raises(jwt.InvalidSignatureError):
            verify_access_token(token, other_public, _test_config)

    def test_expired_token_fails(self):
        now = datetime.now(UTC)
        payload = {
            "sub": str(self.user_id),
            "email": "test@example.com",
            "roles": [],
            "ver": 0,
            "iat": now - timedelta(hours=1),
            "exp": now - timedelta(minutes=1),  # expired 1 minute ago
            "iss": _test_config.jwt_issuer,
        }
        token = jwt.encode(
            payload,
            self.private_pem,
            algorithm="RS256",
            headers={"kid": self.kid},
        )

        with pytest.raises(jwt.ExpiredSignatureError):
            verify_access_token(token, self.public_pem, _test_config)

    def test_token_with_empty_roles(self):
        token = create_access_token(
            user_id=self.user_id,
            email="test@example.com",
            roles=[],
            token_version=5,
            kid=self.kid,
            private_key=self.private_pem,
            config=_test_config,
        )

        payload = verify_access_token(token, self.public_pem, _test_config)
        assert payload["roles"] == []
        assert payload["ver"] == 5

    def test_token_with_multiple_roles(self):
        token = create_access_token(
            user_id=self.user_id,
            email="admin@example.com",
            roles=["user", "admin", "editor"],
            token_version=0,
            kid=self.kid,
            private_key=self.private_pem,
            config=_test_config,
        )

        payload = verify_access_token(token, self.public_pem, _test_config)
        assert payload["roles"] == ["user", "admin", "editor"]
