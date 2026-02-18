"""Tests for the event hooks system — registry, collector, and integration."""

import logging
import uuid

import pytest
from httpx import AsyncClient

from authfort import AuthFort
from authfort.events import (
    Event,
    EventCollector,
    HookRegistry,
    Login,
    LoginFailed,
    Logout,
    OAuthLink,
    RoleAdded,
    RoleRemoved,
    SessionRevoked,
    TokenRefreshed,
    UserBanned,
    UserCreated,
    UserUnbanned,
)

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


# ---------------------------------------------------------------------------
# Unit tests: HookRegistry
# ---------------------------------------------------------------------------


class TestHookRegistry:
    async def test_register_valid_event(self):
        registry = HookRegistry()
        registry.register("user_created", lambda e: None)
        assert len(registry.get_hooks("user_created")) == 1

    async def test_register_invalid_event_raises(self):
        registry = HookRegistry()
        with pytest.raises(ValueError, match="Unknown event"):
            registry.register("not_a_real_event", lambda e: None)

    async def test_multiple_hooks_per_event(self):
        registry = HookRegistry()
        registry.register("login", lambda e: None)
        registry.register("login", lambda e: None)
        registry.register("login", lambda e: None)
        assert len(registry.get_hooks("login")) == 3

    async def test_emit_async_callback(self):
        registry = HookRegistry()
        captured = []

        async def handler(event):
            captured.append(event)

        registry.register("user_created", handler)
        event = UserCreated(email="test@example.com")
        await registry.emit("user_created", event)
        assert len(captured) == 1
        assert captured[0].email == "test@example.com"

    async def test_emit_sync_callback(self):
        registry = HookRegistry()
        captured = []

        def handler(event):
            captured.append(event)

        registry.register("user_created", handler)
        await registry.emit("user_created", UserCreated(email="test@example.com"))
        assert len(captured) == 1

    async def test_emit_failing_callback_continues(self):
        registry = HookRegistry()
        captured = []

        async def bad_handler(event):
            raise RuntimeError("boom")

        async def good_handler(event):
            captured.append(event)

        registry.register("login", bad_handler)
        registry.register("login", good_handler)
        await registry.emit("login", Login(email="test@example.com"))
        assert len(captured) == 1

    async def test_emit_logs_errors(self, caplog):
        registry = HookRegistry()

        async def bad_handler(event):
            raise RuntimeError("hook failed")

        registry.register("login", bad_handler)
        with caplog.at_level(logging.ERROR, logger="authfort.events"):
            await registry.emit("login", Login())
        assert "Hook error" in caplog.text
        assert "hook failed" in caplog.text

    async def test_emit_no_hooks_is_noop(self):
        registry = HookRegistry()
        await registry.emit("login", Login())  # Should not raise


# ---------------------------------------------------------------------------
# Unit tests: EventCollector
# ---------------------------------------------------------------------------


class TestEventCollector:
    async def test_collect_and_flush(self):
        registry = HookRegistry()
        captured = []

        async def handler(event):
            captured.append(event)

        registry.register("user_created", handler)

        collector = EventCollector(registry)
        collector.collect("user_created", UserCreated(email="test@example.com"))
        assert len(captured) == 0  # Not emitted yet
        await collector.flush()
        assert len(captured) == 1

    async def test_flush_clears_pending(self):
        registry = HookRegistry()
        captured = []
        registry.register("login", lambda e: captured.append(e))

        collector = EventCollector(registry)
        collector.collect("login", Login())
        await collector.flush()
        await collector.flush()  # Second flush should be noop
        assert len(captured) == 1

    async def test_collect_multiple_events(self):
        registry = HookRegistry()
        captured = []
        registry.register("user_created", lambda e: captured.append(("created", e)))
        registry.register("login", lambda e: captured.append(("login", e)))

        collector = EventCollector(registry)
        collector.collect("user_created", UserCreated())
        collector.collect("login", Login())
        await collector.flush()
        assert len(captured) == 2
        assert captured[0][0] == "created"
        assert captured[1][0] == "login"

    async def test_flush_with_no_events(self):
        registry = HookRegistry()
        collector = EventCollector(registry)
        await collector.flush()  # Should not raise


# ---------------------------------------------------------------------------
# Integration tests: events via AuthFort + FastAPI
# ---------------------------------------------------------------------------


class TestSignupEvents:
    async def test_signup_fires_user_created_and_login(self, auth: AuthFort, client: AsyncClient):
        created_events = []
        login_events = []

        @auth.on("user_created")
        async def on_created(event):
            created_events.append(event)

        @auth.on("login")
        async def on_login(event):
            login_events.append(event)

        email, data = await _signup(client)

        assert len(created_events) == 1
        assert created_events[0].email == email
        assert created_events[0].provider == "email"
        assert created_events[0].user_id == uuid.UUID(data["user"]["id"])

        assert len(login_events) == 1
        assert login_events[0].email == email
        assert login_events[0].provider == "email"


class TestLoginEvents:
    async def test_login_fires_login_event(self, auth: AuthFort, client: AsyncClient):
        login_events = []

        @auth.on("login")
        async def on_login(event):
            login_events.append(event)

        email, _ = await _signup(client)
        login_events.clear()  # Clear signup login event

        resp = await _login(client, email)
        assert resp.status_code == 200

        assert len(login_events) == 1
        assert login_events[0].email == email
        assert login_events[0].provider == "email"

    async def test_login_failed_fires_event(self, auth: AuthFort, client: AsyncClient):
        failed_events = []

        @auth.on("login_failed")
        async def on_failed(event):
            failed_events.append(event)

        email, _ = await _signup(client)

        resp = await _login(client, email, password="wrongpassword")
        assert resp.status_code == 401

        assert len(failed_events) == 1
        assert failed_events[0].email == email
        assert failed_events[0].reason == "invalid_credentials"

    async def test_login_failed_banned_user(self, auth: AuthFort, client: AsyncClient):
        failed_events = []

        @auth.on("login_failed")
        async def on_failed(event):
            failed_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])
        await auth.ban_user(user_id)

        resp = await _login(client, email)
        assert resp.status_code == 403

        assert len(failed_events) == 1
        assert failed_events[0].reason == "user_banned"


class TestRefreshEvents:
    async def test_refresh_fires_token_refreshed(self, auth: AuthFort, client: AsyncClient):
        refresh_events = []

        @auth.on("token_refreshed")
        async def on_refresh(event):
            refresh_events.append(event)

        email, data = await _signup(client)
        refresh_token = data["tokens"]["refresh_token"]

        resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200

        assert len(refresh_events) == 1
        assert refresh_events[0].user_id == uuid.UUID(data["user"]["id"])


class TestLogoutEvents:
    async def test_logout_fires_logout_event(self, auth: AuthFort, client: AsyncClient):
        logout_events = []

        @auth.on("logout")
        async def on_logout(event):
            logout_events.append(event)

        email, data = await _signup(client)
        refresh_token = data["tokens"]["refresh_token"]

        resp = await client.post("/auth/logout", json={"refresh_token": refresh_token})
        assert resp.status_code == 204

        assert len(logout_events) == 1
        assert logout_events[0].user_id == uuid.UUID(data["user"]["id"])


class TestBanUnbanEvents:
    async def test_ban_fires_user_banned(self, auth: AuthFort, client: AsyncClient):
        banned_events = []

        @auth.on("user_banned")
        async def on_banned(event):
            banned_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)

        assert len(banned_events) == 1
        assert banned_events[0].user_id == user_id

    async def test_unban_fires_user_unbanned(self, auth: AuthFort, client: AsyncClient):
        unbanned_events = []

        @auth.on("user_unbanned")
        async def on_unbanned(event):
            unbanned_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.ban_user(user_id)
        await auth.unban_user(user_id)

        assert len(unbanned_events) == 1
        assert unbanned_events[0].user_id == user_id


class TestRoleEvents:
    async def test_add_role_fires_role_added(self, auth: AuthFort, client: AsyncClient):
        role_events = []

        @auth.on("role_added")
        async def on_role(event):
            role_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.add_role(user_id, "admin")

        assert len(role_events) == 1
        assert role_events[0].user_id == user_id
        assert role_events[0].role == "admin"

    async def test_remove_role_fires_role_removed(self, auth: AuthFort, client: AsyncClient):
        role_events = []

        @auth.on("role_removed")
        async def on_role(event):
            role_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.add_role(user_id, "editor")
        await auth.remove_role(user_id, "editor")

        assert len(role_events) == 1
        assert role_events[0].role == "editor"


class TestSessionEvents:
    async def test_revoke_session_fires_event(self, auth: AuthFort, client: AsyncClient):
        session_events = []

        @auth.on("session_revoked")
        async def on_revoke(event):
            session_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        sessions = await auth.get_sessions(user_id)
        await auth.revoke_session(sessions[0].id)

        assert len(session_events) == 1
        assert session_events[0].session_id == sessions[0].id
        assert session_events[0].revoke_all is False

    async def test_revoke_all_sessions_fires_event(self, auth: AuthFort, client: AsyncClient):
        session_events = []

        @auth.on("session_revoked")
        async def on_revoke(event):
            session_events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.revoke_all_sessions(user_id)

        assert len(session_events) == 1
        assert session_events[0].revoke_all is True
        assert session_events[0].user_id == user_id


class TestEdgeCases:
    async def test_hook_error_does_not_break_signup(self, auth: AuthFort, client: AsyncClient):
        @auth.on("user_created")
        async def bad_hook(event):
            raise RuntimeError("hook exploded")

        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email, "password": "testpassword123",
        })
        assert resp.status_code == 201
        assert resp.json()["user"]["email"] == email

    async def test_no_hooks_registered_works_fine(self, client: AsyncClient):
        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email, "password": "testpassword123",
        })
        assert resp.status_code == 201

    async def test_add_hook_programmatic(self, auth: AuthFort, client: AsyncClient):
        captured = []
        auth.add_hook("login", lambda e: captured.append(e))

        email, _ = await _signup(client)
        # Signup also fires login
        assert len(captured) == 1
