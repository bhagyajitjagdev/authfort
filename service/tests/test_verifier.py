"""Tests for the JWT verifier — token verification using JWKS keys."""

import time

import httpx
import pytest

from authfort_service.jwks import JWKSFetcher
from authfort_service.verifier import JWTVerifier, TokenPayload, TokenVerificationError
from conftest import create_test_token

pytestmark = pytest.mark.asyncio


def _patch_fetcher(monkeypatch, jwks_response):
    """Patch httpx.AsyncClient to return mock JWKS response."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks_response)

    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        original_init(self_client, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


class TestJWTVerifier:
    async def test_verify_valid_token(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher)

        token = create_test_token(private_pem, test_kid, email="user@example.com", roles=["admin"])
        payload = await verifier.verify(token)

        assert isinstance(payload, TokenPayload)
        assert payload.email == "user@example.com"
        assert payload.roles == ["admin"]
        assert payload.name == "Test User"
        assert payload.iss == "authfort"

    async def test_verify_expired_token(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher)

        token = create_test_token(private_pem, test_kid, expires_in=-10)

        with pytest.raises(TokenVerificationError, match="expired"):
            await verifier.verify(token)

    async def test_verify_wrong_issuer(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher, issuer="expected-issuer")

        token = create_test_token(private_pem, test_kid, issuer="wrong-issuer")

        with pytest.raises(TokenVerificationError, match="Invalid"):
            await verifier.verify(token)

    async def test_verify_missing_kid(self, monkeypatch, jwks_response):
        _patch_fetcher(monkeypatch, jwks_response)
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher)

        # Create a JWT without kid in header
        import jwt
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        token = jwt.encode(
            {"sub": "user", "email": "test@example.com", "roles": [], "ver": 1,
             "iat": now, "exp": now + timedelta(seconds=900), "iss": "authfort"},
            "secret", algorithm="HS256",
        )

        with pytest.raises(TokenVerificationError):
            await verifier.verify(token)

    async def test_verify_unknown_kid(self, rsa_key_pair, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json", min_refetch_interval=0,
        )
        verifier = JWTVerifier(fetcher)

        token = create_test_token(private_pem, "unknown-kid-12345")

        with pytest.raises(TokenVerificationError, match="Unknown signing key"):
            await verifier.verify(token)

    async def test_verify_malformed_token(self, monkeypatch, jwks_response):
        _patch_fetcher(monkeypatch, jwks_response)
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher)

        with pytest.raises(TokenVerificationError, match="Malformed"):
            await verifier.verify("not.a.valid.token")

    async def test_verify_returns_all_fields(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair
        fetcher = JWKSFetcher("http://test/.well-known/jwks.json")
        verifier = JWTVerifier(fetcher)

        user_id = "550e8400-e29b-41d4-a716-446655440000"
        token = create_test_token(
            private_pem, test_kid,
            user_id=user_id,
            email="hello@example.com",
            roles=["admin", "editor"],
            token_version=3,
        )
        payload = await verifier.verify(token)

        assert payload.sub == user_id
        assert payload.email == "hello@example.com"
        assert payload.roles == ["admin", "editor"]
        assert payload.token_version == 3
        assert payload.iss == "authfort"
        assert isinstance(payload.exp, int)
        assert isinstance(payload.iat, int)
