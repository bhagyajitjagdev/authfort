"""Tests for the core OAuth flow with a mock provider — covers oauth_authenticate."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from authfort import AuthFort, CookieConfig, GoogleProvider
from authfort.core.auth import AuthError
from authfort.core.oauth import (
    OAuthState,
    OAuthStateData,
    create_oauth_state,
    oauth_authenticate,
    verify_oauth_state,
)
from authfort.events import EventCollector, HookRegistry
from authfort.providers.base import OAuthProvider, OAuthUserInfo

from conftest import TEST_DATABASE_URL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_provider(
    email: str | None = None,
    email_verified: bool = True,
    name: str = "Mock User",
    avatar_url: str = "https://example.com/avatar.jpg",
) -> MagicMock:
    """Create a mock OAuth provider with a unique email per test."""
    unique = uuid.uuid4().hex[:8]
    if email is None:
        email = f"oauth-{unique}@example.com"

    provider = MagicMock(spec=OAuthProvider)
    provider.name = "mock"
    provider.client_id = "mock-id"
    provider.client_secret = "mock-secret"
    provider.redirect_uri = None
    provider.scopes = ("openid", "email")
    provider.authorize_url = "https://mock.example.com/auth"
    provider.token_url = "https://mock.example.com/token"

    provider.exchange_code = AsyncMock(return_value={
        "access_token": "mock-access-token",
        "refresh_token": "mock-refresh-token",
    })
    provider.get_user_info = AsyncMock(return_value=OAuthUserInfo(
        provider="mock",
        provider_account_id=f"mock-uid-{unique}",
        email=email,
        email_verified=email_verified,
        name=name,
        avatar_url=avatar_url,
        access_token="mock-access-token",
    ))
    provider.get_authorization_url = MagicMock(
        return_value="https://mock.example.com/auth?state=xyz",
    )
    return provider


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_provider():
    return _make_mock_provider()


@pytest.fixture
async def auth():
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        providers=[
            GoogleProvider(client_id="test-id", client_secret="test-secret"),
        ],
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


# ---------------------------------------------------------------------------
# OAuth authenticate (core flow)
# ---------------------------------------------------------------------------


class TestOAuthAuthenticate:
    """Test oauth_authenticate with mocked providers."""

    async def test_new_user_created(self, auth: AuthFort, mock_provider):
        """First-time OAuth login creates a new user."""
        async with auth.get_session() as session:
            result = await oauth_authenticate(
                session,
                config=auth.config,
                provider=mock_provider,
                code="auth-code",
                redirect_uri="http://localhost/callback",
            )
            await session.commit()

        assert "@example.com" in result.user.email
        assert result.user.name == "Mock User"
        assert result.tokens.access_token is not None

    async def test_returning_user_recognized(self, auth: AuthFort, mock_provider):
        """Second OAuth login finds the existing user."""
        # First login — creates user
        async with auth.get_session() as session:
            result1 = await oauth_authenticate(
                session, config=auth.config, provider=mock_provider,
                code="code1", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        # Second login — finds existing account
        async with auth.get_session() as session:
            result2 = await oauth_authenticate(
                session, config=auth.config, provider=mock_provider,
                code="code2", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        assert result1.user.id == result2.user.id

    async def test_autolink_existing_email(self, auth: AuthFort):
        """OAuth auto-links to existing user with same email."""
        email = f"autolink-{uuid.uuid4().hex[:8]}@example.com"
        result = await auth.create_user(email, "password123")
        existing_user_id = result.user.id

        provider = _make_mock_provider(email=email)
        async with auth.get_session() as session:
            oauth_result = await oauth_authenticate(
                session, config=auth.config, provider=provider,
                code="code", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        assert oauth_result.user.id == existing_user_id

    async def test_exchange_code_failure(self, auth: AuthFort, mock_provider):
        """Failed code exchange raises AuthError."""
        mock_provider.exchange_code.side_effect = RuntimeError("Connection refused")

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="Failed to exchange OAuth code"):
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="bad-code", redirect_uri="http://localhost/cb",
                )

    async def test_no_access_token_in_response(self, auth: AuthFort, mock_provider):
        """Provider returns empty access_token."""
        mock_provider.exchange_code.return_value = {"token_type": "bearer"}

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="No access token"):
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="code", redirect_uri="http://localhost/cb",
                )

    async def test_get_user_info_failure(self, auth: AuthFort, mock_provider):
        """Failed user info fetch raises AuthError."""
        mock_provider.get_user_info.side_effect = RuntimeError("API down")

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="Failed to fetch user info"):
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="code", redirect_uri="http://localhost/cb",
                )

    async def test_banned_returning_user(self, auth: AuthFort, mock_provider):
        """Banned returning user cannot OAuth login."""
        # Create via OAuth first
        async with auth.get_session() as session:
            result = await oauth_authenticate(
                session, config=auth.config, provider=mock_provider,
                code="code", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        # Ban the user
        await auth.ban_user(result.user.id)

        # Try login again
        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="banned"):
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="code2", redirect_uri="http://localhost/cb",
                )

    async def test_banned_autolink_user(self, auth: AuthFort):
        """Banned user cannot be auto-linked via OAuth."""
        email = f"banned-link-{uuid.uuid4().hex[:8]}@example.com"
        result = await auth.create_user(email, "password123")
        await auth.ban_user(result.user.id)

        provider = _make_mock_provider(email=email)
        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="banned"):
                await oauth_authenticate(
                    session, config=auth.config, provider=provider,
                    code="code", redirect_uri="http://localhost/cb",
                )

    async def test_events_collected_new_user(self, auth: AuthFort, mock_provider):
        """UserCreated and Login events are collected for new OAuth user."""
        hooks = HookRegistry()
        events = EventCollector(hooks)

        async with auth.get_session() as session:
            await oauth_authenticate(
                session, config=auth.config, provider=mock_provider,
                code="code", redirect_uri="http://localhost/cb",
                events=events,
            )
            await session.commit()

        collected_types = [type(e).__name__ for _, e in events._pending]
        assert "UserCreated" in collected_types
        assert "Login" in collected_types

    async def test_events_collected_autolink(self, auth: AuthFort):
        """OAuthLink event collected when linking to existing user."""
        email = f"link-evt-{uuid.uuid4().hex[:8]}@example.com"
        await auth.create_user(email, "password123")

        provider = _make_mock_provider(email=email)
        hooks = HookRegistry()
        events = EventCollector(hooks)

        async with auth.get_session() as session:
            await oauth_authenticate(
                session, config=auth.config, provider=provider,
                code="code", redirect_uri="http://localhost/cb",
                events=events,
            )
            await session.commit()

        collected_types = [type(e).__name__ for _, e in events._pending]
        assert "OAuthLink" in collected_types
        assert "Login" in collected_types

    async def test_profile_fields_filled_from_oauth(self, auth: AuthFort, mock_provider):
        """OAuth fills in missing name and avatar_url."""
        async with auth.get_session() as session:
            result = await oauth_authenticate(
                session, config=auth.config, provider=mock_provider,
                code="code", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        assert result.user.name == "Mock User"
        assert result.user.avatar_url == "https://example.com/avatar.jpg"

    async def test_email_verified_updated_on_autolink(self, auth: AuthFort):
        """OAuth auto-link updates email_verified if provider says verified."""
        email = f"verify-{uuid.uuid4().hex[:8]}@example.com"
        result = await auth.create_user(email, "password123")
        assert result.user.email_verified is False

        provider = _make_mock_provider(email=email)
        async with auth.get_session() as session:
            oauth_result = await oauth_authenticate(
                session, config=auth.config, provider=provider,
                code="code", redirect_uri="http://localhost/cb",
            )
            await session.commit()

        assert oauth_result.user.email_verified is True

    async def test_exchange_code_auth_error_passthrough(self, auth: AuthFort, mock_provider):
        """AuthError from exchange_code is passed through, not wrapped."""
        mock_provider.exchange_code.side_effect = AuthError(
            "Custom error", code="custom_error", status_code=400,
        )

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="Custom error") as exc_info:
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="code", redirect_uri="http://localhost/cb",
                )
            assert exc_info.value.code == "custom_error"

    async def test_get_user_info_auth_error_passthrough(self, auth: AuthFort, mock_provider):
        """AuthError from get_user_info is passed through."""
        mock_provider.get_user_info.side_effect = AuthError(
            "No email", code="oauth_no_email", status_code=400,
        )

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="No email") as exc_info:
                await oauth_authenticate(
                    session, config=auth.config, provider=mock_provider,
                    code="code", redirect_uri="http://localhost/cb",
                )
            assert exc_info.value.code == "oauth_no_email"


# ---------------------------------------------------------------------------
# OAuth state creation and verification
# ---------------------------------------------------------------------------


class TestOAuthState:
    async def test_create_and_verify_state(self, auth: AuthFort):
        """Round-trip: create state, verify it, get back data."""
        async with auth.get_session() as session:
            state = await create_oauth_state(
                session, config=auth.config, provider_name="google",
                redirect_to="/dashboard", mode="redirect",
            )
            await session.commit()

        assert state.state is not None
        assert state.code_verifier is not None
        assert state.code_challenge is not None

        async with auth.get_session() as session:
            data = await verify_oauth_state(
                session, config=auth.config, state=state.state,
                expected_provider="google",
            )

        assert data.redirect_to == "/dashboard"
        assert data.mode == "redirect"
        assert data.code_verifier == state.code_verifier

    async def test_verify_invalid_state(self, auth: AuthFort):
        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="Invalid OAuth state"):
                await verify_oauth_state(
                    session, config=auth.config, state="garbage",
                    expected_provider="google",
                )

    async def test_verify_provider_mismatch(self, auth: AuthFort):
        async with auth.get_session() as session:
            state = await create_oauth_state(
                session, config=auth.config, provider_name="google",
            )
            await session.commit()

        async with auth.get_session() as session:
            with pytest.raises(AuthError, match="provider mismatch"):
                await verify_oauth_state(
                    session, config=auth.config, state=state.state,
                    expected_provider="github",
                )

    async def test_state_without_redirect_or_mode(self, auth: AuthFort):
        async with auth.get_session() as session:
            state = await create_oauth_state(
                session, config=auth.config, provider_name="google",
            )
            await session.commit()

        async with auth.get_session() as session:
            data = await verify_oauth_state(
                session, config=auth.config, state=state.state,
                expected_provider="google",
            )

        assert data.redirect_to is None
        assert data.mode is None
