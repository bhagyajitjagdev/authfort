"""Tests for cleanup APIs, user profile, has_role, get_jwks, rsa_key_size,
update_user, UserUpdated event, OAuth scope validation, redirect_to, popup mode,
provider tokens, and signup with avatar_url/phone."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from authfort import AuthFort
from authfort.events import UserUpdated
from authfort.providers.base import OAuthUserInfo

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


async def _signup(client, email=None, password="testpassword123", **extra):
    email = email or unique_email()
    body = {"email": email, "password": password, **extra}
    resp = await client.post("/auth/signup", json=body)
    assert resp.status_code == 201
    return email, resp.json()


def _get_state_from_redirect(response) -> str:
    location = response.headers["location"]
    parsed = urlparse(location)
    return parse_qs(parsed.query)["state"][0]


# ---------------------------------------------------------------------------
# has_role
# ---------------------------------------------------------------------------


class TestHasRole:
    async def test_has_role_true(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.add_role(user_id, "admin")
        assert await auth.has_role(user_id, "admin") is True

    async def test_has_role_false(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        assert await auth.has_role(user_id, "admin") is False

    async def test_has_role_after_remove(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.add_role(user_id, "editor")
        assert await auth.has_role(user_id, "editor") is True

        await auth.remove_role(user_id, "editor")
        assert await auth.has_role(user_id, "editor") is False


# ---------------------------------------------------------------------------
# cleanup_expired_sessions
# ---------------------------------------------------------------------------


class TestCleanupExpiredSessions:
    async def test_cleanup_returns_count(self, auth: AuthFort, client: AsyncClient):
        # Clean slate: remove any existing expired/revoked tokens first
        await auth.cleanup_expired_sessions()

        await _signup(client)
        deleted = await auth.cleanup_expired_sessions()
        assert deleted == 0

    async def test_cleanup_deletes_revoked_tokens(self, auth: AuthFort, client: AsyncClient):
        # Clean slate first
        await auth.cleanup_expired_sessions()

        email, data = await _signup(client)
        refresh_token = data["tokens"]["refresh_token"]

        # Logout revokes the refresh token
        await client.post("/auth/logout", json={"refresh_token": refresh_token})

        deleted = await auth.cleanup_expired_sessions()
        assert deleted >= 1

    async def test_cleanup_deletes_expired_tokens(self, auth: AuthFort, client: AsyncClient):
        # Clean slate first
        await auth.cleanup_expired_sessions()

        email, data = await _signup(client)

        # Manually expire the refresh token
        async with auth.get_session() as session:
            from sqlalchemy import select
            from authfort.models.refresh_token import RefreshToken

            stmt = select(RefreshToken)
            result = (await session.execute(stmt)).scalars()
            for rt in result.all():
                rt.expires_at = datetime.now(UTC) - timedelta(hours=1)
                session.add(rt)

        deleted = await auth.cleanup_expired_sessions()
        assert deleted >= 1


# ---------------------------------------------------------------------------
# get_jwks (programmatic)
# ---------------------------------------------------------------------------


class TestGetJWKS:
    async def test_get_jwks_returns_keys_after_signup(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        jwks = await auth.get_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1
        assert jwks["keys"][0]["kty"] == "RSA"
        assert jwks["keys"][0]["use"] == "sig"

    async def test_get_jwks_returns_dict_with_keys_list(self, auth: AuthFort):
        jwks = await auth.get_jwks()
        assert "keys" in jwks
        assert isinstance(jwks["keys"], list)

    async def test_get_jwks_matches_endpoint(self, auth: AuthFort, client: AsyncClient):
        await _signup(client)
        programmatic = await auth.get_jwks()
        endpoint_resp = await client.get("/.well-known/jwks.json")
        endpoint_data = endpoint_resp.json()

        assert len(programmatic["keys"]) == len(endpoint_data["keys"])
        prog_kids = {k["kid"] for k in programmatic["keys"]}
        ep_kids = {k["kid"] for k in endpoint_data["keys"]}
        assert prog_kids == ep_kids


# ---------------------------------------------------------------------------
# rsa_key_size
# ---------------------------------------------------------------------------


class TestRSAKeySize:
    async def test_default_key_size_is_2048(self):
        auth = AuthFort(database_url="sqlite+aiosqlite:///test_ks.db")
        assert auth.config.rsa_key_size == 2048
        await auth.dispose()

    async def test_custom_key_size(self):
        auth = AuthFort(database_url="sqlite+aiosqlite:///test_ks.db", rsa_key_size=4096)
        assert auth.config.rsa_key_size == 4096
        await auth.dispose()

    async def test_key_size_below_2048_raises(self):
        with pytest.raises(ValueError, match="rsa_key_size must be >= 2048"):
            AuthFort(database_url="sqlite+aiosqlite:///test_ks.db", rsa_key_size=1024)


# ---------------------------------------------------------------------------
# update_user
# ---------------------------------------------------------------------------


class TestUpdateUser:
    async def test_update_name(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client, name="Original")
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, name="Updated")
        assert result.name == "Updated"
        assert result.email == email

    async def test_update_phone(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, phone="+1234567890")
        assert result.phone == "+1234567890"

    async def test_update_avatar_url(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, avatar_url="https://example.com/avatar.jpg")
        assert result.avatar_url == "https://example.com/avatar.jpg"

    async def test_update_multiple_fields(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, name="New Name", phone="+999")
        assert result.name == "New Name"
        assert result.phone == "+999"

    async def test_clear_field_with_none(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client, name="Has Name")
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, name=None)
        assert result.name is None

    async def test_update_no_fields_raises(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        with pytest.raises(ValueError, match="No fields to update"):
            await auth.update_user(user_id)

    async def test_update_nonexistent_user_raises(self, auth: AuthFort):
        from authfort import AuthError

        fake_id = uuid.uuid4()
        with pytest.raises(AuthError):
            await auth.update_user(fake_id, name="Ghost")

    async def test_update_preserves_other_fields(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client, name="Keep This")
        user_id = uuid.UUID(data["user"]["id"])

        result = await auth.update_user(user_id, phone="+111")
        assert result.name == "Keep This"
        assert result.phone == "+111"
        assert result.email == email


# ---------------------------------------------------------------------------
# UserUpdated event
# ---------------------------------------------------------------------------


class TestUserUpdatedEvent:
    async def test_update_user_fires_event(self, auth: AuthFort, client: AsyncClient):
        events = []

        @auth.on("user_updated")
        async def on_updated(event):
            events.append(event)

        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        await auth.update_user(user_id, name="New Name", phone="+123")

        assert len(events) == 1
        assert events[0].user_id == user_id
        assert set(events[0].fields) == {"name", "phone"}


# ---------------------------------------------------------------------------
# Signup with avatar_url and phone
# ---------------------------------------------------------------------------


class TestSignupWithProfile:
    async def test_signup_with_avatar_url(self, client: AsyncClient):
        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "avatar_url": "https://example.com/avatar.png",
        })
        assert resp.status_code == 201
        assert resp.json()["user"]["avatar_url"] == "https://example.com/avatar.png"

    async def test_signup_with_phone(self, client: AsyncClient):
        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "phone": "+1234567890",
        })
        assert resp.status_code == 201
        assert resp.json()["user"]["phone"] == "+1234567890"

    async def test_signup_with_all_profile_fields(self, client: AsyncClient):
        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "name": "Full Profile",
            "avatar_url": "https://example.com/photo.jpg",
            "phone": "+5551234",
        })
        assert resp.status_code == 201
        user = resp.json()["user"]
        assert user["name"] == "Full Profile"
        assert user["avatar_url"] == "https://example.com/photo.jpg"
        assert user["phone"] == "+5551234"

    async def test_signup_phone_in_me_endpoint(self, client: AsyncClient):
        email = unique_email()
        resp = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "phone": "+999",
        })
        assert resp.status_code == 201
        token = resp.json()["tokens"]["access_token"]

        me_resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_resp.status_code == 200
        assert me_resp.json()["phone"] == "+999"

    async def test_programmatic_create_user_with_profile(self, auth: AuthFort):
        email = unique_email()
        result = await auth.create_user(
            email, "testpassword123",
            name="Prog User",
            avatar_url="https://example.com/prog.jpg",
            phone="+111222333",
        )
        assert result.user.avatar_url == "https://example.com/prog.jpg"
        assert result.user.phone == "+111222333"


# ---------------------------------------------------------------------------
# OAuth scope validation (extra_scopes / REQUIRED_SCOPES)
# ---------------------------------------------------------------------------


class TestOAuthScopes:
    async def test_google_required_scopes(self):
        from authfort import GoogleProvider

        p = GoogleProvider(client_id="id", client_secret="secret")
        assert "openid" in p.scopes
        assert "email" in p.scopes
        assert "profile" in p.scopes

    async def test_github_required_scopes(self):
        from authfort import GitHubProvider

        p = GitHubProvider(client_id="id", client_secret="secret")
        assert "read:user" in p.scopes
        assert "user:email" in p.scopes

    async def test_extra_scopes_are_appended(self):
        from authfort import GoogleProvider

        p = GoogleProvider(
            client_id="id", client_secret="secret",
            extra_scopes=("https://www.googleapis.com/auth/calendar",),
        )
        assert "https://www.googleapis.com/auth/calendar" in p.scopes
        # Required scopes still present
        assert "openid" in p.scopes

    async def test_duplicate_scopes_are_deduplicated(self):
        from authfort import GoogleProvider

        p = GoogleProvider(
            client_id="id", client_secret="secret",
            extra_scopes=("openid", "email", "custom"),
        )
        scope_list = list(p.scopes)
        assert scope_list.count("openid") == 1
        assert scope_list.count("email") == 1
        assert "custom" in scope_list

    async def test_scopes_in_authorization_url(self):
        from authfort import GoogleProvider

        p = GoogleProvider(
            client_id="id", client_secret="secret",
            extra_scopes=("https://www.googleapis.com/auth/drive",),
        )
        url = p.get_authorization_url(
            redirect_uri="http://localhost/callback",
            state="test-state",
        )
        assert "drive" in url
        assert "openid" in url


# ---------------------------------------------------------------------------
# OAuth redirect_to
# ---------------------------------------------------------------------------


class TestOAuthRedirectTo:
    async def test_authorize_with_redirect_to(self, oauth_client: AsyncClient):
        resp = await oauth_client.get(
            "/auth/oauth/google/authorize",
            params={"redirect_to": "/dashboard"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    async def test_authorize_rejects_absolute_redirect(self, oauth_client: AsyncClient):
        resp = await oauth_client.get(
            "/auth/oauth/google/authorize",
            params={"redirect_to": "https://evil.com"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_redirect"

    async def test_callback_redirects_to_redirect_to(self, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Redirect User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize",
                params={"redirect_to": "/dashboard"},
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
                follow_redirects=False,
            )

        assert callback_res.status_code == 302
        assert callback_res.headers["location"] == "/dashboard"

    async def test_callback_without_redirect_returns_json(self, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="JSON User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize",
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        assert "user" in callback_res.json()
        assert "tokens" in callback_res.json()


# ---------------------------------------------------------------------------
# OAuth popup mode
# ---------------------------------------------------------------------------


class TestOAuthPopupMode:
    async def test_popup_mode_returns_html(self, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Popup User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize",
                params={"mode": "popup"},
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        assert "text/html" in callback_res.headers["content-type"]
        body = callback_res.text
        assert "window.opener.postMessage" in body
        assert "window.close()" in body

    async def test_popup_mode_html_contains_user_data(self, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Popup Data User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize",
                params={"mode": "popup"},
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        body = callback_res.text
        assert user_info.email in body


# ---------------------------------------------------------------------------
# Provider tokens
# ---------------------------------------------------------------------------


class TestProviderTokens:
    async def test_get_provider_tokens_after_oauth(self, auth_with_oauth: AuthFort, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Token User",
            access_token="the-provider-access-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "the-provider-access-token", "refresh_token": "the-provider-refresh-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)
            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        user_id = uuid.UUID(callback_res.json()["user"]["id"])

        tokens = await auth_with_oauth.get_provider_tokens(user_id, "google")
        assert tokens is not None
        assert tokens["access_token"] == "the-provider-access-token"
        assert tokens["refresh_token"] == "the-provider-refresh-token"

    async def test_get_provider_tokens_no_account(self, auth: AuthFort, client: AsyncClient):
        email, data = await _signup(client)
        user_id = uuid.UUID(data["user"]["id"])

        tokens = await auth.get_provider_tokens(user_id, "google")
        assert tokens is None

    async def test_get_provider_tokens_wrong_provider(self, auth_with_oauth: AuthFort, oauth_client: AsyncClient):
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Wrong Provider User",
            access_token="google-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)
            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        user_id = uuid.UUID(callback_res.json()["user"]["id"])

        # Ask for github tokens — user only has google
        tokens = await auth_with_oauth.get_provider_tokens(user_id, "github")
        assert tokens is None


# ---------------------------------------------------------------------------
# frontend_url — cross-origin OAuth redirects
# ---------------------------------------------------------------------------


class TestFrontendUrl:
    async def test_redirect_prepends_frontend_url(self, frontend_oauth_client: AsyncClient):
        """When frontend_url is set, redirect_to is prefixed with it."""
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="Frontend URL User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await frontend_oauth_client.get(
                "/auth/oauth/google/authorize",
                params={"redirect_to": "/dashboard"},
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await frontend_oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
                follow_redirects=False,
            )

        assert callback_res.status_code == 302
        assert callback_res.headers["location"] == "https://app.example.com/dashboard"

    async def test_no_redirect_to_returns_json_with_frontend_url(self, frontend_oauth_client: AsyncClient):
        """When no redirect_to is given, frontend_url doesn't affect the response."""
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=unique_email(),
            email_verified=True,
            name="No Redirect User",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await frontend_oauth_client.get(
                "/auth/oauth/google/authorize",
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await frontend_oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        assert "user" in callback_res.json()

    async def test_frontend_url_trailing_slash_stripped(self):
        """frontend_url with trailing slash is normalized."""
        auth = AuthFort(
            database_url="sqlite+aiosqlite:///test.db",
            frontend_url="https://app.example.com/",
        )
        assert auth.config.frontend_url == "https://app.example.com"
        await auth.dispose()

    async def test_frontend_url_none_by_default(self):
        """frontend_url defaults to None."""
        auth = AuthFort(database_url="sqlite+aiosqlite:///test.db")
        assert auth.config.frontend_url is None
        await auth.dispose()


# ---------------------------------------------------------------------------
# Event exports
# ---------------------------------------------------------------------------


class TestEventExports:
    async def test_all_events_exported_from_init(self):
        from authfort import (
            KeyRotated,
            Login,
            LoginFailed,
            Logout,
            OAuthLink,
            PasswordChanged,
            PasswordReset,
            PasswordResetRequested,
            RoleAdded,
            RoleRemoved,
            SessionRevoked,
            TokenRefreshed,
            UserBanned,
            UserCreated,
            UserUnbanned,
            UserUpdated,
        )
        # Just verify they're importable (no assertion needed — import would fail)
        assert UserUpdated is not None
