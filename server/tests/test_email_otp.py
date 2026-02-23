"""Tests for email OTP passwordless login — generate, create, verify."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from authfort import AuthError, AuthFort, CookieConfig
from authfort.core.refresh import generate_otp
from authfort.db import get_session
from authfort.repositories import user as user_repo
from authfort.repositories import verification_token as vt_repo
from conftest import TEST_DATABASE_URL

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
# TestGenerateOTP — unit tests, no fixtures needed
# ---------------------------------------------------------------------------


class TestGenerateOTP:
    async def test_generates_6_digits(self):
        code, code_hash = generate_otp()

        assert len(code) == 6
        assert code.isdigit()

    async def test_hash_matches(self):
        code, code_hash = generate_otp()

        expected_hash = hashlib.sha256(code.encode()).hexdigest()
        assert code_hash == expected_hash

    async def test_different_codes(self):
        code1, _ = generate_otp()
        code2, _ = generate_otp()

        assert code1 != code2


# ---------------------------------------------------------------------------
# TestCreateEmailOTP
# ---------------------------------------------------------------------------


class TestCreateEmailOTP:
    async def test_returns_6_digit_code(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        code = await auth.create_email_otp(email)

        assert code is not None
        assert len(code) == 6
        assert code.isdigit()

    async def test_returns_none_for_unknown_email(self, auth: AuthFort):
        result = await auth.create_email_otp("nonexistent@example.com")

        assert result is None

    async def test_returns_none_for_banned_user(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        await auth.ban_user(user_id)

        result = await auth.create_email_otp(email)

        assert result is None

    async def test_auto_creates_user_when_passwordless_signup(self, auth_passwordless: AuthFort):
        email = unique_email()

        code = await auth_passwordless.create_email_otp(email)

        assert code is not None
        assert len(code) == 6
        assert code.isdigit()

    async def test_event_fired(self, auth: AuthFort):
        events = []
        auth.add_hook("email_otp_requested", lambda e: events.append(e))

        email, user_id, _ = await _create_user(auth)
        code = await auth.create_email_otp(email)

        assert len(events) == 1
        assert events[0].email == email
        assert events[0].code == code


# ---------------------------------------------------------------------------
# TestVerifyEmailOTP
# ---------------------------------------------------------------------------


class TestVerifyEmailOTP:
    async def test_successful_login(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        code = await auth.create_email_otp(email)
        assert code is not None

        result = await auth.verify_email_otp(email, code)

        assert result.tokens.access_token
        assert result.tokens.refresh_token
        assert result.user.email == email

    async def test_also_verifies_email(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        code = await auth.create_email_otp(email)
        assert code is not None

        await auth.verify_email_otp(email, code)

        async with get_session(auth._session_factory) as session:
            user = await user_repo.get_user_by_id(session, user_id)
            assert user.email_verified is True

    async def test_code_one_time_use(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        code = await auth.create_email_otp(email)
        assert code is not None

        # First use succeeds
        await auth.verify_email_otp(email, code)

        # Second use fails
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email_otp(email, code)
        assert exc_info.value.code == "invalid_otp"

    async def test_wrong_code_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        await auth.create_email_otp(email)

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email_otp(email, "invalid_otp")
        assert exc_info.value.code == "invalid_otp"

    async def test_expired_code_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)

        # Manually create an already-expired OTP token
        raw_code, code_hash = generate_otp()
        expired_at = datetime.now(UTC) - timedelta(hours=1)

        async with get_session(auth._session_factory) as session:
            await vt_repo.create_verification_token(
                session,
                user_id=user_id,
                token_hash=code_hash,
                type="email_otp",
                expires_at=expired_at,
            )

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email_otp(email, raw_code)
        assert exc_info.value.code == "invalid_otp"

    async def test_wrong_email_rejected(self, auth: AuthFort):
        email_a, user_id_a, _ = await _create_user(auth)
        email_b, user_id_b, _ = await _create_user(auth)

        code = await auth.create_email_otp(email_a)
        assert code is not None

        # Verify with user B's email but user A's code
        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email_otp(email_b, code)
        assert exc_info.value.code == "invalid_otp"

    async def test_banned_user_rejected(self, auth: AuthFort):
        email, user_id, _ = await _create_user(auth)
        code = await auth.create_email_otp(email)
        assert code is not None

        await auth.ban_user(user_id)

        with pytest.raises(AuthError) as exc_info:
            await auth.verify_email_otp(email, code)
        assert exc_info.value.code == "user_banned"
