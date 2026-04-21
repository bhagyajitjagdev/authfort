"""Tests for refresh token cross-check (Phase 14 item 3).

Defends against cookie-swap attacks where an attacker replaces the refresh_token
cookie with a different user's refresh_token while leaving access_token intact.
"""

import pytest

from authfort import AuthError, AuthFort

from conftest import unique_email

pytestmark = pytest.mark.asyncio


async def _login_user(auth: AuthFort, password="testpassword123"):
    """Create a user and return (email, access_token, refresh_token)."""
    email = unique_email()
    result = await auth.create_user(email, password)
    return email, result.tokens.access_token, result.tokens.refresh_token


class TestRefreshCrossCheck:
    async def test_normal_refresh_with_matching_tokens(self, auth: AuthFort):
        email, access, refresh = await _login_user(auth)
        result = await auth.refresh(refresh, access_token_cookie=access)
        assert result.tokens.access_token

    async def test_no_access_token_cookie_allows_refresh(self, auth: AuthFort):
        """Bearer-mode clients don't send access tokens on refresh — backward compat."""
        email, _, refresh = await _login_user(auth)
        # access_token_cookie=None → skip check.
        result = await auth.refresh(refresh, access_token_cookie=None)
        assert result.tokens.access_token

    async def test_malformed_access_token_does_not_block(self, auth: AuthFort):
        email, _, refresh = await _login_user(auth)
        result = await auth.refresh(refresh, access_token_cookie="not.a.jwt")
        assert result.tokens.access_token

    async def test_swap_attack_rejected(self, auth: AuthFort):
        """U1 access + U2 refresh → 401 refresh_token_mismatch, U2 token revoked."""
        _, u1_access, _ = await _login_user(auth)
        _, _, u2_refresh = await _login_user(auth)

        with pytest.raises(AuthError) as exc_info:
            await auth.refresh(u2_refresh, access_token_cookie=u1_access)
        assert exc_info.value.code == "refresh_token_mismatch"
        assert exc_info.value.status_code == 401

        # U2's refresh token should now be revoked — using it again fails.
        with pytest.raises(AuthError):
            await auth.refresh(u2_refresh, access_token_cookie=None)

    async def test_expired_matching_access_token_still_works(self, auth: AuthFort):
        """Access token can be legitimately expired — that's why we're refreshing."""
        import jwt as pyjwt
        from datetime import UTC, datetime, timedelta

        email, access, refresh = await _login_user(auth)

        # Forge an already-expired access token signed with the same user's
        # session by re-signing the claims with exp in the past.
        # Decode the real access token to get claims.
        unverified = pyjwt.decode(access, options={"verify_signature": False})
        unverified["exp"] = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())

        # Fetch the actual signing key material.
        from authfort.db import get_session
        from authfort.repositories import signing_key as sk_repo

        async with get_session(auth.session_factory) as session:
            sk = await sk_repo.get_current_signing_key(session)

        expired_token = pyjwt.encode(
            unverified, sk.private_key, algorithm="RS256", headers={"kid": sk.kid},
        )

        result = await auth.refresh(refresh, access_token_cookie=expired_token)
        assert result.tokens.access_token

    async def test_sid_mismatch_same_user_rejected(self, auth: AuthFort):
        """Same user, two separate sessions — access from session A, refresh from
        session B should also reject. Tighter bind than sub-only."""
        import jwt as pyjwt

        email = unique_email()
        # First session.
        r1 = await auth.create_user(email, "testpassword123")
        # Second session — login again.
        r2 = await auth.login(email, "testpassword123")

        # access from r1 has sid=session_1, refresh from r2 has session_id=session_2.
        with pytest.raises(AuthError) as exc_info:
            await auth.refresh(r2.tokens.refresh_token, access_token_cookie=r1.tokens.access_token)
        assert exc_info.value.code == "refresh_token_mismatch"

    async def test_event_emitted_on_mismatch(self, auth: AuthFort):
        events = []
        auth.add_hook("refresh_token_mismatch", lambda e: events.append(e))

        _, u1_access, _ = await _login_user(auth)
        _, _, u2_refresh = await _login_user(auth)

        with pytest.raises(AuthError):
            await auth.refresh(u2_refresh, access_token_cookie=u1_access)

        assert len(events) == 1
