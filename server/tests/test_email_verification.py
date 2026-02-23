"""Tests for email verification — token creation, verification, and endpoint."""

import uuid
from datetime import UTC, timedelta, datetime

import pytest
from httpx import AsyncClient

from authfort import AuthFort, AuthError
from authfort.core.refresh import generate_refresh_token
from authfort.db import get_session
from authfort.repositories import user as user_repo
from authfort.repositories import verification_token as vt_repo

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


async def _create_user(auth: AuthFort, email=None, password="testpassword123"):
    """Create a user via signup and return (email, user_id, auth_response)."""
    from authfort.core.auth import signup
    from authfort.events import EventCollector, HookRegistry

    email = email or unique_email()
    collector = EventCollector(HookRegistry())
    async with get_session(auth._session_factory) as session:
        result = await signup(
            session,
            config=auth._config,
            email=email,
            password=password,
            events=collector,
        )
    return email, result.user.id, result


# ---------------------------------------------------------------------------
# TestCreateEmailVerificationToken
# ---------------------------------------------------------------------------


class TestCreateEmailVerificationToken:
    async def test_returns_token_for_unverified_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_email_verification_token(user_id)

        assert token is not None
        assert len(token) > 20

    async def test_returns_none_for_already_verified_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # Manually mark as verified
        async with get_session(auth._session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            await user_repo.update_user(session, user, email_verified=True)

        token = await auth.create_email_verification_token(user_id)

        assert token is None

    async def test_returns_none_for_unknown_user_id(self, auth: AuthFort):
        token = await auth.create_email_verification_token(uuid.uuid4())

        assert token is None

    async def test_replaces_old_tokens(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token1 = await auth.create_email_verification_token(user_id)
        token2 = await auth.create_email_verification_token(user_id)

        assert token1 is not None
        assert token2 is not None
        assert token1 != token2

        # First token should no longer be valid
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email(token1)
        assert exc_info.value.code == "invalid_verification_token"

        # Second token should still work
        result = await auth.verify_email(token2)
        assert result is True

    async def test_event_fired(self, auth: AuthFort):
        events = []
        auth.add_hook("email_verification_requested", lambda e: events.append(e))

        email, user_id, _ = await _create_user(auth)
        token = await auth.create_email_verification_token(user_id)

        assert len(events) == 1
        assert events[0].email == email
        assert events[0].token == token


# ---------------------------------------------------------------------------
# TestVerifyEmail
# ---------------------------------------------------------------------------


class TestVerifyEmail:
    async def test_successful_verification(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_email_verification_token(user_id)
        assert token is not None

        result = await auth.verify_email(token)
        assert result is True

        # Confirm in DB
        async with get_session(auth._session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            assert user.email_verified is True

    async def test_token_is_one_time_use(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_email_verification_token(user_id)
        assert token is not None

        result = await auth.verify_email(token)
        assert result is True

        # Second use should fail
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email(token)
        assert exc_info.value.code == "invalid_verification_token"

    async def test_invalid_token_rejected(self, auth: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email("bogus")
        assert exc_info.value.code == "invalid_verification_token"

    async def test_expired_token_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # Manually create an already-expired token
        raw_token, token_hash = generate_refresh_token()
        expired_at = datetime.now(UTC) - timedelta(hours=1)

        async with get_session(auth._session_factory) as session:
            await vt_repo.create_verification_token(
                session,
                user_id=user_id,
                token_hash=token_hash,
                type="email_verify",
                expires_at=expired_at,
            )

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email(raw_token)
        assert exc_info.value.code == "invalid_verification_token"

    async def test_event_fired(self, auth: AuthFort):
        events = []
        auth.add_hook("email_verified", lambda e: events.append(e))

        email, user_id, _ = await _create_user(auth)

        token = await auth.create_email_verification_token(user_id)
        assert token is not None
        await auth.verify_email(token)

        assert len(events) == 1
        assert events[0].email == email

    async def test_endpoint_success(self, auth: AuthFort, client: AsyncClient):
        email, user_id, _ = await _create_user(auth)

        token = await auth.create_email_verification_token(user_id)
        assert token is not None

        resp = await client.post("/auth/verify-email", json={"token": token})
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_endpoint_bad_token(self, client: AsyncClient):
        resp = await client.post("/auth/verify-email", json={"token": "bad"})
        assert resp.status_code == 400
