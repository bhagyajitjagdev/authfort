"""Tests for JWKS endpoint, key rotation, key cleanup, and introspection."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from authfort import AuthFort

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


async def _signup(client, email=None, password="testpassword123"):
    email = email or unique_email()
    resp = await client.post("/auth/signup", json={"email": email, "password": password})
    assert resp.status_code == 201
    return email, resp.json()


# ---------------------------------------------------------------------------
# JWKS endpoint
# ---------------------------------------------------------------------------


class TestJWKSEndpoint:
    async def test_jwks_returns_valid_keyset(self, client: AsyncClient):
        # Trigger key creation via signup
        await _signup(client)

        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1

        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key

    async def test_jwks_has_cache_headers(self, client: AsyncClient):
        await _signup(client)
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        assert "max-age" in resp.headers.get("cache-control", "")

    async def test_jwks_only_public_keys(self, client: AsyncClient):
        await _signup(client)
        resp = await client.get("/.well-known/jwks.json")
        data = resp.json()
        for key in data["keys"]:
            # Private key components must never appear
            assert "d" not in key
            assert "p" not in key
            assert "q" not in key
            assert "dp" not in key
            assert "dq" not in key
            assert "qi" not in key

    async def test_jwks_no_auth_required(self, client: AsyncClient):
        # Should work without any Authorization header
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200

    async def test_jwks_kid_matches_token(self, client: AsyncClient):
        """The kid in JWKS should match the kid in issued JWTs."""
        import jwt

        _, data = await _signup(client)
        token = data["tokens"]["access_token"]
        header = jwt.get_unverified_header(token)
        token_kid = header["kid"]

        resp = await client.get("/.well-known/jwks.json")
        jwks = resp.json()
        kids = [k["kid"] for k in jwks["keys"]]
        assert token_kid in kids


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


class TestKeyRotation:
    async def test_rotate_key_creates_new_key(self, auth: AuthFort, client: AsyncClient):
        # Trigger initial key creation
        await _signup(client)

        resp = await client.get("/.well-known/jwks.json")
        old_kids = [k["kid"] for k in resp.json()["keys"]]

        new_kid = await auth.rotate_key()
        assert new_kid not in old_kids

    async def test_rotate_key_old_key_gets_expiry(self, auth: AuthFort, client: AsyncClient):
        """After rotation, old key should have expires_at set."""
        await _signup(client)

        resp = await client.get("/.well-known/jwks.json")
        old_kid = resp.json()["keys"][0]["kid"]

        await auth.rotate_key()

        # Check old key has expires_at via repository
        from authfort.repositories import signing_key as signing_key_repo

        async with auth.get_session() as session:
            old_key = await signing_key_repo.get_signing_key_by_kid(session, old_kid)
            assert old_key is not None
            assert old_key.expires_at is not None
            assert old_key.is_current is False

    async def test_jwks_contains_both_keys_after_rotation(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        await auth.rotate_key()

        resp = await client.get("/.well-known/jwks.json")
        keys = resp.json()["keys"]
        assert len(keys) >= 2

    async def test_old_tokens_still_verify_after_rotation(self, auth: AuthFort, client: AsyncClient):
        """Tokens signed with old key should still verify (old key not yet expired)."""
        email, data = await _signup(client)
        old_token = data["tokens"]["access_token"]

        await auth.rotate_key()

        # Old token should still work for /auth/me
        resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == email

    async def test_rotate_key_fires_event(self, auth: AuthFort, client: AsyncClient):
        events = []

        @auth.on("key_rotated")
        async def on_rotated(event):
            events.append(event)

        await _signup(client)
        new_kid = await auth.rotate_key()

        assert len(events) == 1
        assert events[0].new_kid == new_kid
        assert events[0].old_kid != ""


# ---------------------------------------------------------------------------
# Key cleanup
# ---------------------------------------------------------------------------


class TestKeyCleanup:
    async def test_cleanup_expired_keys_deletes_old(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        await auth.rotate_key()

        # Manually set old key expires_at to the past
        from authfort.repositories import signing_key as signing_key_repo

        async with auth.get_session() as session:
            keys = await signing_key_repo.get_all_signing_keys(session)
            old_key = [k for k in keys if not k.is_current][0]
            old_key.expires_at = datetime.now(UTC) - timedelta(hours=1)
            session.add(old_key)

        deleted = await auth.cleanup_expired_keys()
        assert deleted >= 1

    async def test_cleanup_returns_count(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        # No expired keys yet
        deleted = await auth.cleanup_expired_keys()
        assert deleted == 0

    async def test_cleanup_does_not_delete_current_key(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        await auth.rotate_key()

        # Expire old key
        from authfort.repositories import signing_key as signing_key_repo

        async with auth.get_session() as session:
            keys = await signing_key_repo.get_all_signing_keys(session)
            for k in keys:
                if not k.is_current:
                    k.expires_at = datetime.now(UTC) - timedelta(hours=1)
                    session.add(k)

        await auth.cleanup_expired_keys()

        # JWKS should still have the current key
        resp = await client.get("/.well-known/jwks.json")
        assert len(resp.json()["keys"]) >= 1

    async def test_jwks_excludes_expired_keys(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        await auth.rotate_key()

        # Expire old key
        from authfort.repositories import signing_key as signing_key_repo

        async with auth.get_session() as session:
            keys = await signing_key_repo.get_all_signing_keys(session)
            old_key = [k for k in keys if not k.is_current][0]
            old_key.expires_at = datetime.now(UTC) - timedelta(hours=1)
            session.add(old_key)

        resp = await client.get("/.well-known/jwks.json")
        kids = [k["kid"] for k in resp.json()["keys"]]
        # Only the current key should be present
        assert len(kids) == 1


# ---------------------------------------------------------------------------
# Introspection endpoint
# ---------------------------------------------------------------------------


class TestIntrospection:
    async def test_introspect_valid_token(self, client: AsyncClient):
        email, data = await _signup(client)
        token = data["tokens"]["access_token"]

        resp = await client.post("/auth/introspect", json={"token": token})
        assert resp.status_code == 200
        result = resp.json()
        assert result["active"] is True
        assert result["email"] == email
        assert result["sub"] == data["user"]["id"]
        assert isinstance(result["roles"], list)
        assert result["iss"] == "authfort"

    async def test_introspect_garbage_token(self, client: AsyncClient):
        resp = await client.post("/auth/introspect", json={"token": "not.a.real.token"})
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    async def test_introspect_expired_token(self, auth: AuthFort, client: AsyncClient):
        """Create a token with 1-second expiry, wait, then introspect."""
        import time

        # Use a very short TTL auth instance
        from authfort import CookieConfig

        short_auth = AuthFort(
            database_url=auth.config.database_url,
            access_token_ttl=1,
            cookie=CookieConfig(secure=False),
        )
        async with short_auth._engine.begin() as conn:
            from authfort.models import Base
            await conn.run_sync(Base.metadata.create_all)
        try:
            from fastapi import FastAPI
            from httpx import ASGITransport

            app = FastAPI()
            app.include_router(short_auth.fastapi_router(), prefix="/auth")

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                _, data = await _signup(c)
                token = data["tokens"]["access_token"]
                time.sleep(2)
                # Introspect via the main client (same DB, same keys)
                resp = await client.post("/auth/introspect", json={"token": token})
                assert resp.status_code == 200
                assert resp.json()["active"] is False
        finally:
            await short_auth.dispose()

    async def test_introspect_banned_user(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        token = data["tokens"]["access_token"]
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)

        resp = await client.post("/auth/introspect", json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    async def test_introspect_token_version_mismatch(self, auth: AuthFort, client: AsyncClient):
        """Adding a role bumps token_version, making old tokens stale."""
        email, data = await _signup(client)
        old_token = data["tokens"]["access_token"]
        user_id = uuid.UUID(data["user"]["id"])

        await auth.add_role(user_id, "admin")

        resp = await client.post("/auth/introspect", json={"token": old_token})
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    async def test_introspect_returns_fresh_roles(self, auth: AuthFort, client: AsyncClient):
        """Introspection returns roles from DB, not from JWT."""
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        # Add role without immediate invalidation (lazy)
        await auth.add_role(user_id, "editor", immediate=False)

        # Re-login to get fresh token with current token_version
        login_resp = await client.post("/auth/login", json={"email": email, "password": "testpassword123"})
        fresh_token = login_resp.json()["tokens"]["access_token"]

        resp = await client.post("/auth/introspect", json={"token": fresh_token})
        result = resp.json()
        assert result["active"] is True
        assert "editor" in result["roles"]


class TestIntrospectionAuth:
    async def test_introspect_with_secret_required(self, secret_client: AsyncClient, auth_with_secret: AuthFort):
        """When secret is configured, requests without it get 401."""
        email, data = await _signup(secret_client)
        token = data["tokens"]["access_token"]

        # No Authorization header
        resp = await secret_client.post("/auth/introspect", json={"token": token})
        assert resp.status_code == 401

    async def test_introspect_with_correct_secret(self, secret_client: AsyncClient, auth_with_secret: AuthFort):
        email, data = await _signup(secret_client)
        token = data["tokens"]["access_token"]

        resp = await secret_client.post(
            "/auth/introspect",
            json={"token": token},
            headers={"Authorization": "Bearer test-secret-123"},
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is True

    async def test_introspect_with_wrong_secret(self, secret_client: AsyncClient, auth_with_secret: AuthFort):
        email, data = await _signup(secret_client)
        token = data["tokens"]["access_token"]

        resp = await secret_client.post(
            "/auth/introspect",
            json={"token": token},
            headers={"Authorization": "Bearer wrong-secret"},
        )
        assert resp.status_code == 401
