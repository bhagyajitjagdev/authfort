"""Tests for session management — listing and revoking sessions."""

import uuid

import pytest

from authfort import AuthFort

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


async def _signup(client, email=None, password="testpassword123"):
    """Helper: signup and return (email, response_data)."""
    email = email or unique_email()
    resp = await client.post("/auth/signup", json={"email": email, "password": password})
    assert resp.status_code == 201
    return email, resp.json()


async def _login(client, email, password="testpassword123"):
    """Helper: login and return response data."""
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()


class TestGetSessions:
    async def test_new_user_has_one_session(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        sessions = await auth.get_sessions(user_id)
        assert len(sessions) == 1
        assert sessions[0].revoked is False

    async def test_multiple_logins_create_multiple_sessions(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        # Login twice more
        await _login(client, email)
        await _login(client, email)

        sessions = await auth.get_sessions(user_id)
        # signup + 2 logins = 3 sessions
        assert len(sessions) == 3

    async def test_sessions_ordered_newest_first(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await _login(client, email)

        sessions = await auth.get_sessions(user_id)
        assert len(sessions) == 2
        assert sessions[0].created_at >= sessions[1].created_at

    async def test_active_only_filters_revoked(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await _login(client, email)

        sessions = await auth.get_sessions(user_id)
        assert len(sessions) == 2

        # Revoke the first session
        await auth.revoke_session(sessions[1].id)

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 1

        all_sessions = await auth.get_sessions(user_id)
        assert len(all_sessions) == 2

    async def test_session_has_expected_fields(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        sessions = await auth.get_sessions(user_id)
        s = sessions[0]
        assert s.id is not None
        assert s.created_at is not None
        assert s.expires_at is not None
        assert s.revoked is False
        # user_agent and ip_address may be None in test client

    async def test_empty_for_unknown_user(self, auth: AuthFort):
        sessions = await auth.get_sessions(uuid.uuid4())
        assert sessions == []


class TestRevokeSession:
    async def test_revoke_specific_session(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await _login(client, email)
        await _login(client, email)

        sessions = await auth.get_sessions(user_id, active_only=True)
        assert len(sessions) == 3

        # Revoke the middle session
        result = await auth.revoke_session(sessions[1].id)
        assert result is True

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 2

    async def test_revoke_returns_false_for_unknown_id(self, auth: AuthFort):
        result = await auth.revoke_session(uuid.uuid4())
        assert result is False

    async def test_revoke_returns_false_if_already_revoked(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        sessions = await auth.get_sessions(user_id)
        session_id = sessions[0].id

        # Revoke once
        assert await auth.revoke_session(session_id) is True
        # Revoke again
        assert await auth.revoke_session(session_id) is False

    async def test_revoked_session_refresh_fails(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])
        refresh_token = data["tokens"]["refresh_token"]

        # Revoke the session
        sessions = await auth.get_sessions(user_id)
        await auth.revoke_session(sessions[0].id)

        # Try to refresh — should fail
        resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 401


class TestRevokeAllSessions:
    async def test_revoke_all_sessions(self, auth: AuthFort, client):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await _login(client, email)
        await _login(client, email)

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 3

        await auth.revoke_all_sessions(user_id)

        active = await auth.get_sessions(user_id, active_only=True)
        assert len(active) == 0

        all_sessions = await auth.get_sessions(user_id)
        assert all(s.revoked for s in all_sessions)

    async def test_revoke_all_does_not_affect_other_users(self, auth: AuthFort, client):
        email1, data1 = await _signup(client)
        user1_id = uuid.UUID(data1["user"]["id"])

        email2, data2 = await _signup(client)
        user2_id = uuid.UUID(data2["user"]["id"])

        await auth.revoke_all_sessions(user1_id)

        # User 1 has no active sessions
        assert len(await auth.get_sessions(user1_id, active_only=True)) == 0
        # User 2 still has their session
        assert len(await auth.get_sessions(user2_id, active_only=True)) == 1


class TestSessionResponseSerialization:
    async def test_session_response_is_serializable(self, auth: AuthFort, client):
        """SessionResponse should be JSON-serializable (Pydantic model)."""
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        sessions = await auth.get_sessions(user_id)
        # Should not raise
        json_data = sessions[0].model_dump(mode="json")
        assert "id" in json_data
        assert "created_at" in json_data
        assert "expires_at" in json_data
        assert "revoked" in json_data
