"""Tests for magic link passwordless login — create token and verify."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from authfort import AuthError, AuthFort, CookieConfig
from authfort.core.refresh import generate_refresh_token
from authfort.db import get_session
from authfort.repositories import user as user_repo
from authfort.repositories import verification_token as vt_repo
from conftest import TEST_DATABASE_URL

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


async def _create_user(auth: AuthFort, email=None, password="testpassword123"):
    """Create a user and return (email, user_id, auth_response)."""
    email = email or unique_email()
    result = await auth.create_user(email, password)
    user_id = result.user.id
    return email, user_id, result


@pytest_asyncio.fixture
async def auth_passwordless():
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        allow_passwordless_signup=True,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


# ---------------------------------------------------------------------------
# TestCreateMagicLinkToken
# ---------------------------------------------------------------------------


class TestCreateMagicLinkToken:
    async def test_returns_token_for_existing_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_returns_none_for_unknown_email(self, auth: AuthFort):
        token = await auth.create_magic_link_token("nonexistent@example.com")

        assert token is None

    async def test_returns_none_for_banned_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        await auth.ban_user(user_id)

        token = await auth.create_magic_link_token(email)
        assert token is None

    async def test_auto_creates_user_when_passwordless_signup(self, auth_passwordless: AuthFort):
        events = []
        auth_passwordless.add_hook("user_created", lambda e: events.append(e))

        email = unique_email()
        token = await auth_passwordless.create_magic_link_token(email)

        assert token is not None
        assert len(events) == 1
        assert events[0].email == email
        assert events[0].provider == "magic_link"

    async def test_replaces_old_tokens(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token1 = await auth.create_magic_link_token(email)
        token2 = await auth.create_magic_link_token(email)

        assert token1 is not None
        assert token2 is not None
        assert token1 != token2

        # First token should be invalidated (replaced)
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_magic_link(token1)
        assert exc_info.value.code == "invalid_magic_link"

        # Second token should still work
        result = await auth.verify_magic_link(token2)
        assert result.tokens.access_token
        assert result.user.email == email

    async def test_event_fired(self, auth: AuthFort):
        events = []
        auth.add_hook("magic_link_requested", lambda e: events.append(e))

        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)

        assert len(events) == 1
        assert events[0].email == email
        assert events[0].token == token


# ---------------------------------------------------------------------------
# TestVerifyMagicLink
# ---------------------------------------------------------------------------


class TestVerifyMagicLink:
    async def test_successful_login(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)
        result = await auth.verify_magic_link(token)

        assert result.tokens.access_token
        assert result.tokens.refresh_token
        assert result.user.email == email

    async def test_also_verifies_email(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # By default, email_verified is False after create_user
        token = await auth.create_magic_link_token(email)
        await auth.verify_magic_link(token)

        # After magic link login, email_verified should be True
        async with get_session(auth.session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            assert user.email_verified is True

    async def test_already_verified_stays_true(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # Manually set email_verified=True first
        async with get_session(auth.session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            await user_repo.update_user(session, user, email_verified=True)

        token = await auth.create_magic_link_token(email)
        await auth.verify_magic_link(token)

        # Should still be True
        async with get_session(auth.session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            assert user.email_verified is True

    async def test_token_one_time_use(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)

        # First use succeeds
        result = await auth.verify_magic_link(token)
        assert result.tokens.access_token

        # Second use fails — token was deleted
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_magic_link(token)
        assert exc_info.value.code == "invalid_magic_link"

    async def test_invalid_token_rejected(self, auth: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_magic_link("totally-bogus-token")
        assert exc_info.value.code == "invalid_magic_link"

    async def test_expired_token_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # Manually create an expired magic_link token
        raw_token, token_hash = generate_refresh_token()
        expired_at = datetime.now(UTC) - timedelta(hours=1)

        async with get_session(auth.session_factory) as session:
            await vt_repo.create_verification_token(
                session,
                user_id=user_id,
                token_hash=token_hash,
                type="magic_link",
                expires_at=expired_at,
            )

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_magic_link(raw_token)
        assert exc_info.value.code == "invalid_magic_link"

    async def test_banned_user_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)

        # Ban the user after token creation
        await auth.ban_user(user_id)

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_magic_link(token)
        assert exc_info.value.code == "user_banned"

    async def test_event_fired(self, auth: AuthFort):
        events = []
        auth.add_hook("magic_link_login", lambda e: events.append(e))

        email, user_id, _ = await _create_user(auth)

        token = await auth.create_magic_link_token(email)
        await auth.verify_magic_link(token)

        assert len(events) == 1
        assert events[0].email == email
