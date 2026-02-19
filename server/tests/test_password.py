"""Tests for password reset and change password functionality."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from authfort import AuthError, AuthFort

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _create_user(auth: AuthFort, email=None, password="testpassword123"):
    """Create a user and return (email, user_id, auth_response)."""
    email = email or unique_email()
    result = await auth.create_user(email, password)
    user_id = result.user.id
    return email, user_id, result


# ---------------------------------------------------------------------------
# Password Reset Token
# ---------------------------------------------------------------------------

class TestCreatePasswordResetToken:
    async def test_returns_token_for_existing_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        token = await auth.create_password_reset_token(email)
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20

    async def test_returns_none_for_unknown_email(self, auth: AuthFort):
        token = await auth.create_password_reset_token("nobody@example.com")
        assert token is None

    async def test_returns_none_for_oauth_only_user(self, auth: AuthFort):
        """OAuth-only users have no password_hash, so reset shouldn't work."""
        # Create a user via OAuth (simulate by creating with password then clearing it)
        from authfort.db import get_session
        from authfort.repositories import user as user_repo

        email = unique_email()
        _, user_id, _ = await _create_user(auth, email)

        # Remove password hash to simulate OAuth-only account
        async with get_session(auth.session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            await user_repo.update_user(session, user, password_hash=None)

        token = await auth.create_password_reset_token(email)
        assert token is None

    async def test_replaces_old_tokens(self, auth: AuthFort):
        """Creating a new reset token should delete any previous ones."""
        email, user_id, _ = await _create_user(auth)

        token1 = await auth.create_password_reset_token(email)
        token2 = await auth.create_password_reset_token(email)

        assert token1 != token2

        # Old token should be invalid
        with pytest.raises(AuthError, match="Invalid or expired"):
            await auth.reset_password(token1, "newpassword123")

        # New token should work
        result = await auth.reset_password(token2, "newpassword123")
        assert result is True

    async def test_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("password_reset_requested", lambda e: events_received.append(e))

        email, user_id, _ = await _create_user(auth)
        await auth.create_password_reset_token(email)

        assert len(events_received) == 1
        assert events_received[0].email == email
        assert events_received[0].user_id == user_id

    async def test_no_event_for_unknown_email(self, auth: AuthFort):
        events_received = []
        auth.add_hook("password_reset_requested", lambda e: events_received.append(e))

        await auth.create_password_reset_token("nobody@example.com")

        assert len(events_received) == 0


# ---------------------------------------------------------------------------
# Reset Password
# ---------------------------------------------------------------------------

class TestResetPassword:
    async def test_successful_reset(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        token = await auth.create_password_reset_token(email)

        result = await auth.reset_password(token, "newpassword456")
        assert result is True

    async def test_login_with_new_password_works(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth, password="oldpassword123")
        token = await auth.create_password_reset_token(email)
        await auth.reset_password(token, "newpassword456")

        # New password works
        result = await auth.login(email, "newpassword456")
        assert result.user.email == email

    async def test_old_password_fails_after_reset(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth, password="oldpassword123")
        token = await auth.create_password_reset_token(email)
        await auth.reset_password(token, "newpassword456")

        # Old password fails
        with pytest.raises(AuthError, match="Invalid email or password"):
            await auth.login(email, "oldpassword123")

    async def test_token_is_one_time_use(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        token = await auth.create_password_reset_token(email)

        await auth.reset_password(token, "newpassword1")

        with pytest.raises(AuthError, match="Invalid or expired"):
            await auth.reset_password(token, "newpassword2")

    async def test_invalid_token_rejected(self, auth: AuthFort):
        with pytest.raises(AuthError, match="Invalid or expired"):
            await auth.reset_password("totally-bogus-token", "newpassword")

    async def test_expired_token_rejected(self, auth: AuthFort):
        """Tokens with expired timestamps should be rejected."""
        from authfort.core.refresh import generate_refresh_token, hash_refresh_token
        from authfort.db import get_session
        from authfort.repositories import verification_token as vt_repo

        email, user_id, _ = await _create_user(auth)

        # Manually create an expired token
        raw_token, token_hash = generate_refresh_token()
        expired_at = datetime.now(UTC) - timedelta(hours=1)

        async with get_session(auth.session_factory) as session:
            await vt_repo.create_verification_token(
                session,
                user_id=user_id,
                token_hash=token_hash,
                type="password_reset",
                expires_at=expired_at,
            )

        with pytest.raises(AuthError, match="Invalid or expired"):
            await auth.reset_password(raw_token, "newpassword")

    async def test_token_version_bumped(self, auth: AuthFort):
        """After reset, old JWTs should be invalidated via token_version bump."""
        from authfort.db import get_session
        from authfort.repositories import user as user_repo

        email, user_id, original = await _create_user(auth)

        async with get_session(auth.session_factory) as session:
            user_before = await user_repo.get_user_by_id(session, user_id)
            version_before = user_before.token_version

        token = await auth.create_password_reset_token(email)
        await auth.reset_password(token, "newpassword456")

        async with get_session(auth.session_factory) as session:
            user_after = await user_repo.get_user_by_id(session, user_id)
            assert user_after.token_version > version_before

    async def test_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("password_reset", lambda e: events_received.append(e))

        email, user_id, _ = await _create_user(auth)
        token = await auth.create_password_reset_token(email)
        await auth.reset_password(token, "newpassword456")

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id


# ---------------------------------------------------------------------------
# Change Password
# ---------------------------------------------------------------------------

class TestChangePassword:
    async def test_successful_change(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth, password="oldpassword123")

        await auth.change_password(user_id, "oldpassword123", "newpassword456")

        # New password works
        result = await auth.login(email, "newpassword456")
        assert result.user.email == email

    async def test_old_password_fails_after_change(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth, password="oldpassword123")

        await auth.change_password(user_id, "oldpassword123", "newpassword456")

        with pytest.raises(AuthError, match="Invalid email or password"):
            await auth.login(email, "oldpassword123")

    async def test_wrong_old_password_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth, password="oldpassword123")

        with pytest.raises(AuthError, match="Invalid password"):
            await auth.change_password(user_id, "wrongpassword", "newpassword456")

    async def test_oauth_only_user_rejected(self, auth: AuthFort):
        from authfort.db import get_session
        from authfort.repositories import user as user_repo

        email, user_id, _ = await _create_user(auth)

        # Remove password hash to simulate OAuth-only
        async with get_session(auth.session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            await user_repo.update_user(session, user, password_hash=None)

        with pytest.raises(AuthError, match="social login"):
            await auth.change_password(user_id, "old", "new")

    async def test_user_not_found(self, auth: AuthFort):
        with pytest.raises(AuthError, match="User not found"):
            await auth.change_password(uuid.uuid4(), "old", "new")

    async def test_token_version_bumped(self, auth: AuthFort):
        from authfort.db import get_session
        from authfort.repositories import user as user_repo

        email, user_id, _ = await _create_user(auth, password="oldpassword123")

        async with get_session(auth.session_factory) as session:
            user_before = await user_repo.get_user_by_id(session, user_id)
            version_before = user_before.token_version

        await auth.change_password(user_id, "oldpassword123", "newpassword456")

        async with get_session(auth.session_factory) as session:
            user_after = await user_repo.get_user_by_id(session, user_id)
            assert user_after.token_version > version_before

    async def test_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("password_changed", lambda e: events_received.append(e))

        email, user_id, _ = await _create_user(auth, password="oldpassword123")
        await auth.change_password(user_id, "oldpassword123", "newpassword456")

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id
