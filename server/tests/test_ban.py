"""Tests for user banning — ban/unban, login/refresh/access blocked."""

import uuid

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


async def _login(client, email, password="testpassword123"):
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    return resp


class TestBanUser:
    async def test_ban_user(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)

        # Login should fail with 403
        resp = await _login(client, email)
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "user_banned"

    async def test_banned_user_cannot_refresh(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])
        refresh_token = data["tokens"]["refresh_token"]

        await auth.ban_user(user_id)

        resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
        # Token version was bumped, so it will fail with 401 (revoked)
        assert resp.status_code == 401

    async def test_banned_user_cannot_access_protected_routes(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])
        access_token = data["tokens"]["access_token"]

        await auth.ban_user(user_id)

        # The token version was bumped, so access with old token fails
        resp = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        # Could be 401 (version mismatch) or 403 (banned check) — either way, blocked
        assert resp.status_code in (401, 403)

    async def test_ban_revokes_all_sessions(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        # Create extra sessions
        await _login(client, email)
        await _login(client, email)

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 3

        await auth.ban_user(user_id)

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 0


class TestUnbanUser:
    async def test_unban_allows_login(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)

        # Banned — can't login
        resp = await _login(client, email)
        assert resp.status_code == 403

        await auth.unban_user(user_id)

        # Unbanned — can login again
        resp = await _login(client, email)
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == email

    async def test_unban_allows_protected_access(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)
        await auth.unban_user(user_id)

        # Login fresh (old tokens were invalidated)
        resp = await _login(client, email)
        assert resp.status_code == 200
        new_token = resp.json()["tokens"]["access_token"]

        # Access protected route with fresh token
        resp = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200


class TestBanEdgeCases:
    async def test_ban_does_not_affect_other_users(self, auth: AuthFort, client: AsyncClient):
        email1, data1 = await _signup(client)
        user1_id = uuid.UUID(data1["user"]["id"])

        email2, data2 = await _signup(client)

        await auth.ban_user(user1_id)

        # User 2 can still login
        resp = await _login(client, email2)
        assert resp.status_code == 200

    async def test_ban_nonexistent_user_raises(self, auth: AuthFort):
        with pytest.raises(ValueError):
            await auth.ban_user(uuid.uuid4())

    async def test_unban_nonexistent_user_raises(self, auth: AuthFort):
        with pytest.raises(ValueError):
            await auth.unban_user(uuid.uuid4())

    async def test_double_ban_is_idempotent(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)
        await auth.ban_user(user_id)  # Should not raise

        resp = await _login(client, email)
        assert resp.status_code == 403

    async def test_double_unban_is_idempotent(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)
        await auth.unban_user(user_id)
        await auth.unban_user(user_id)  # Should not raise

        resp = await _login(client, email)
        assert resp.status_code == 200
