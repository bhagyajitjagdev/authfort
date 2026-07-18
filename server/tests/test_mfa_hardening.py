"""Tests for the Phase 17 MFA hardening fixes (F1-F6), v0.0.31.

F1 TOTP replay horizon, F2 brute-force lockout, F3 challenge survives key
rotation, F4 token_version bump on enable/disable, F5 whitespace-tolerant
codes, F6 OAuth MFA redirect uses a URL fragment.
"""

import time
import uuid
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthFort, AuthError, CookieConfig, GoogleProvider
from authfort.providers.base import OAuthUserInfo
from authfort.repositories import user as user_repo
from authfort.repositories import user_mfa as user_mfa_repo
from authfort.utils import utc_now

pytestmark = pytest.mark.asyncio

from conftest import TEST_DATABASE_URL


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


def _next_code(secret: str) -> str:
    return pyotp.TOTP(secret).at(time.time() + 30)


async def _create_user(auth: AuthFort, email=None, password="pass1234!"):
    email = email or unique_email()
    result = await auth.create_user(email, password)
    return email, result.user.id


async def _enable_mfa(auth: AuthFort, user_id: uuid.UUID) -> tuple[str, list[str]]:
    setup = await auth.enable_mfa_init(user_id)
    totp = pyotp.TOTP(setup.secret)
    backup_codes = await auth.enable_mfa_confirm(user_id, totp.now())
    return setup.secret, backup_codes


# ---------------------------------------------------------------------------
# F1 — TOTP replay horizon (integration; unit tests live in test_mfa.py)
# ---------------------------------------------------------------------------


class TestReplayHorizonIntegration:
    async def test_same_totp_code_cannot_be_replayed(self, auth: AuthFort):
        """A code accepted once cannot complete a second login while it is still
        within its validity horizon — even though it lands in an adjacent
        window from the first use."""
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        code = _next_code(secret)

        challenge1 = await auth.login(email, "pass1234!")
        result1 = await auth.complete_mfa_login(challenge1.mfa_token, code)
        assert result1.tokens.access_token

        # Same code, fresh challenge — must be rejected as a replay.
        challenge2 = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError) as exc:
            await auth.complete_mfa_login(challenge2.mfa_token, code)
        assert exc.value.code == "invalid_mfa_code"


# ---------------------------------------------------------------------------
# F2 — brute-force lockout
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_lockout():
    """AuthFort with a low lockout threshold for fast tests."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        check_pwned_passwords=False,
        mfa_max_failed_attempts=3,
        mfa_lockout_seconds=900,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


class TestMFALockout:
    async def test_locks_after_threshold(self, auth_lockout: AuthFort):
        email, user_id = await _create_user(auth_lockout)
        await _enable_mfa(auth_lockout, user_id)

        # 3 wrong attempts (threshold = 3)
        for _ in range(3):
            challenge = await auth_lockout.login(email, "pass1234!")
            with pytest.raises(AuthError) as exc:
                await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")
            assert exc.value.code == "invalid_mfa_code"

        # Now locked — even a correct code is refused with mfa_locked / 429.
        secret = None  # correct code path
        challenge = await auth_lockout.login(email, "pass1234!")
        with pytest.raises(AuthError) as exc:
            await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")
        assert exc.value.code == "mfa_locked"
        assert exc.value.status_code == 429

    async def test_correct_code_blocked_while_locked(self, auth_lockout: AuthFort):
        email, user_id = await _create_user(auth_lockout)
        secret, _ = await _enable_mfa(auth_lockout, user_id)

        for _ in range(3):
            challenge = await auth_lockout.login(email, "pass1234!")
            with pytest.raises(AuthError):
                await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")

        # A valid code is still rejected while the lock holds.
        challenge = await auth_lockout.login(email, "pass1234!")
        with pytest.raises(AuthError) as exc:
            await auth_lockout.complete_mfa_login(challenge.mfa_token, _next_code(secret))
        assert exc.value.code == "mfa_locked"

    async def test_mfa_locked_event_fired_once(self, auth_lockout: AuthFort):
        locks = []
        fails = []
        auth_lockout.add_hook("mfa_locked", lambda e: locks.append(e))
        auth_lockout.add_hook("mfa_failed", lambda e: fails.append(e))

        email, user_id = await _create_user(auth_lockout)
        await _enable_mfa(auth_lockout, user_id)

        # 3 fails to lock, then 2 more attempts while locked
        for _ in range(5):
            challenge = await auth_lockout.login(email, "pass1234!")
            with pytest.raises(AuthError):
                await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")

        # mfa_locked fires once (at the crossing); the locked attempts short-
        # circuit before counting as new failures.
        assert len(locks) == 1
        assert locks[0].user_id == user_id
        assert locks[0].locked_until is not None
        assert len(fails) == 3

    async def test_successful_verify_resets_counter(self, auth_lockout: AuthFort):
        email, user_id = await _create_user(auth_lockout)
        secret, _ = await _enable_mfa(auth_lockout, user_id)

        # 2 fails (below threshold of 3)
        for _ in range(2):
            challenge = await auth_lockout.login(email, "pass1234!")
            with pytest.raises(AuthError):
                await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")

        # Succeed — resets the counter.
        challenge = await auth_lockout.login(email, "pass1234!")
        result = await auth_lockout.complete_mfa_login(challenge.mfa_token, _next_code(secret))
        assert result.tokens.access_token

        async with auth_lockout.get_session() as session:
            mfa = await user_mfa_repo.get_user_mfa(session, user_id)
            assert mfa.failed_attempts == 0
            assert mfa.locked_until is None

    async def test_lock_expires(self, auth_lockout: AuthFort):
        email, user_id = await _create_user(auth_lockout)
        secret, _ = await _enable_mfa(auth_lockout, user_id)

        for _ in range(3):
            challenge = await auth_lockout.login(email, "pass1234!")
            with pytest.raises(AuthError):
                await auth_lockout.complete_mfa_login(challenge.mfa_token, "000000")

        # Force the lock into the past (simulating lockout_seconds elapsing).
        async with auth_lockout.get_session() as session:
            from datetime import timedelta
            mfa = await user_mfa_repo.get_user_mfa(session, user_id)
            mfa.locked_until = utc_now() - timedelta(seconds=1)
            await session.commit()

        # A valid code is accepted again once the lock has expired.
        challenge = await auth_lockout.login(email, "pass1234!")
        result = await auth_lockout.complete_mfa_login(challenge.mfa_token, _next_code(secret))
        assert result.tokens.access_token

    async def test_lockout_disabled_when_zero(self):
        instance = AuthFort(
            database_url=TEST_DATABASE_URL,
            cookie=CookieConfig(secure=False),
            check_pwned_passwords=False,
            mfa_max_failed_attempts=0,
        )
        await instance.migrate()
        try:
            email, user_id = await _create_user(instance)
            await _enable_mfa(instance, user_id)

            # Many failures never lock the account.
            for _ in range(6):
                challenge = await instance.login(email, "pass1234!")
                with pytest.raises(AuthError) as exc:
                    await instance.complete_mfa_login(challenge.mfa_token, "000000")
                assert exc.value.code == "invalid_mfa_code"  # never mfa_locked

            async with instance.get_session() as session:
                mfa = await user_mfa_repo.get_user_mfa(session, user_id)
                assert mfa.locked_until is None
        finally:
            await instance.dispose()

    async def test_lock_returns_429_over_http(self, auth_lockout: AuthFort):
        app = FastAPI()
        app.include_router(auth_lockout.fastapi_router(), prefix="/auth")
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ) as client:
            email, user_id = await _create_user(auth_lockout)
            await _enable_mfa(auth_lockout, user_id)

            for _ in range(3):
                r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
                mfa_token = r.json()["mfa_token"]
                r = await client.post(
                    "/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"},
                )
                assert r.status_code == 401

            r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
            mfa_token = r.json()["mfa_token"]
            r = await client.post(
                "/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"},
            )
            assert r.status_code == 429
            assert r.json()["detail"]["error"] == "mfa_locked"


# ---------------------------------------------------------------------------
# F3 — challenge token survives key rotation
# ---------------------------------------------------------------------------


class TestChallengeAcrossKeyRotation:
    async def test_challenge_valid_after_rotation(self, auth: AuthFort):
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        # Login mints a challenge signed by the current key.
        challenge = await auth.login(email, "pass1234!")

        # Rotate the signing key before the user completes the second step.
        await auth.rotate_key()

        # Challenge still verifies via kid lookup of the (now retired) key.
        result = await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))
        assert result.user.email == email
        assert result.tokens.access_token

    async def test_challenge_invalid_when_key_gone(self, auth: AuthFort):
        """If the signing key is fully removed (not just rotated), the challenge
        can no longer be verified — fails closed, not open."""
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        challenge = await auth.login(email, "pass1234!")

        # Rotate, then delete every signing key so the kid can't resolve and the
        # fallback current key is a brand-new one that didn't sign the token.
        await auth.rotate_key()
        from authfort.models.signing_key import SigningKey
        from sqlalchemy import delete as sa_delete
        async with auth.get_session() as session:
            await session.execute(sa_delete(SigningKey))
            await session.commit()

        with pytest.raises(AuthError) as exc:
            await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))
        assert exc.value.code == "invalid_mfa_token"


# ---------------------------------------------------------------------------
# F4 — token_version bump on enable / disable
# ---------------------------------------------------------------------------


class TestTokenVersionBump:
    async def _get_ver(self, auth: AuthFort, user_id) -> int:
        async with auth.get_session() as session:
            user = await user_repo.get_user_by_id(session, user_id)
            return user.token_version

    async def test_enable_bumps_version(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        before = await self._get_ver(auth, user_id)
        await _enable_mfa(auth, user_id)
        assert await self._get_ver(auth, user_id) == before + 1

    async def test_disable_bumps_version(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        after_enable = await self._get_ver(auth, user_id)
        await auth.disable_mfa(user_id, _next_code(secret))
        assert await self._get_ver(auth, user_id) == after_enable + 1

    async def test_admin_disable_bumps_version(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)
        after_enable = await self._get_ver(auth, user_id)
        await auth.admin_disable_mfa(user_id)
        assert await self._get_ver(auth, user_id) == after_enable + 1

    async def test_new_token_carries_mfa_enabled_claim(self, auth: AuthFort):
        """After enabling MFA and completing login, the issued access token
        reflects mfa_enabled=True."""
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))

        import jwt as pyjwt
        claims = pyjwt.decode(result.tokens.access_token, options={"verify_signature": False})
        assert claims["mfa_enabled"] is True


# ---------------------------------------------------------------------------
# F5 — whitespace-tolerant codes
# ---------------------------------------------------------------------------


class TestWhitespaceInCodes:
    def _spaced(self, code: str) -> str:
        # Authenticator apps display "123 456".
        return code[:3] + " " + code[3:]

    async def test_login_accepts_spaced_code(self, auth: AuthFort):
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, self._spaced(_next_code(secret)))
        assert result.tokens.access_token

    async def test_confirm_accepts_spaced_code(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        setup = await auth.enable_mfa_init(user_id)
        totp = pyotp.TOTP(setup.secret)
        codes = await auth.enable_mfa_confirm(user_id, self._spaced(totp.now()))
        assert len(codes) == 10

    async def test_disable_accepts_spaced_code(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        await auth.disable_mfa(user_id, self._spaced(_next_code(secret)))
        status = await auth.get_mfa_status(user_id)
        assert status.enabled is False

    async def test_surrounding_whitespace_stripped(self, auth: AuthFort):
        email, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)
        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, f"  {_next_code(secret)}  ")
        assert result.tokens.access_token


# ---------------------------------------------------------------------------
# F6 — OAuth MFA redirect uses a URL fragment
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_oauth_frontend():
    """OAuth-enabled instance with a frontend_url so redirects are absolute."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        check_pwned_passwords=False,
        frontend_url="https://app.example.com",
        providers=[GoogleProvider(client_id="gid", client_secret="gsecret")],
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


class TestOAuthMFARedirectFragment:
    async def test_mfa_token_in_fragment_not_query(self, auth_oauth_frontend: AuthFort):
        app = FastAPI()
        app.include_router(auth_oauth_frontend.fastapi_router(), prefix="/auth")

        # Pre-create the user (matching the mocked Google email) + enable MFA so
        # the OAuth callback returns an MFA challenge.
        email = unique_email()
        _, user_id = await _create_user(auth_oauth_frontend, email=email)
        await _enable_mfa(auth_oauth_frontend, user_id)

        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=email,
            email_verified=True,
            name="Google User",
            avatar_url="https://example.com/p.jpg",
            access_token="mock-token",
        )

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token", "token_type": "Bearer"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as client:
                auth_res = await client.get("/auth/oauth/google/authorize", follow_redirects=False)
                state = parse_qs(urlparse(auth_res.headers["location"]).query)["state"][0]

                callback_res = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "mock-code", "state": state},
                    follow_redirects=False,
                )

        assert callback_res.status_code == 302
        location = callback_res.headers["location"]
        parsed = urlparse(location)
        # Token is in the fragment, and NOT in the query string.
        assert parsed.fragment.startswith("mfa_token=")
        assert "mfa_token=" not in (parsed.query or "")
        assert "mfa_token" not in parsed.path
