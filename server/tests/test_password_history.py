"""Tests for password history (Phase 14 item 5) — opt-in via password_history_count."""

import pytest
import pytest_asyncio

from authfort import AuthError, AuthFort, CookieConfig
from authfort.db import get_session
from authfort.repositories import password_history as password_history_repo
from authfort.repositories import user as user_repo

from conftest import TEST_DATABASE_URL, unique_email

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def auth_no_history():
    """AuthFort with password_history_count=0 (default)."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def auth_history_4():
    """AuthFort with password_history_count=4 (PCI-DSS)."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        password_history_count=4,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


async def _create_user(auth: AuthFort, password="testpassword123"):
    email = unique_email()
    result = await auth.create_user(email, password)
    return email, result.user.id


class TestHistoryDisabledByDefault:
    async def test_count_zero_stores_nothing(self, auth_no_history: AuthFort):
        email, user_id = await _create_user(auth_no_history)
        async with get_session(auth_no_history.session_factory) as session:
            rows = await password_history_repo.get_recent_password_hashes(
                session, user_id, limit=10,
            )
        assert rows == []

    async def test_count_zero_allows_reuse_via_reset(self, auth_no_history: AuthFort):
        email, user_id = await _create_user(auth_no_history, password="pw-1234567")
        # Change away then back — with feature off this must succeed.
        await auth_no_history.change_password(user_id, "pw-1234567", "pw-7654321")
        await auth_no_history.change_password(user_id, "pw-7654321", "pw-1234567")
        # No AuthError raised.


class TestHistoryEnforcement:
    async def test_reuse_immediately_rejected(self, auth_history_4: AuthFort):
        email, user_id = await _create_user(auth_history_4, password="pw-original1")
        await auth_history_4.change_password(user_id, "pw-original1", "pw-second12")

        # Try to change back to the original — should reject.
        with pytest.raises(AuthError) as exc_info:
            await auth_history_4.change_password(user_id, "pw-second12", "pw-original1")
        assert exc_info.value.code == "password_reused"
        assert exc_info.value.status_code == 400

    async def test_reuse_within_window_rejected(self, auth_history_4: AuthFort):
        email, user_id = await _create_user(auth_history_4, password="pw-v1-12345")
        await auth_history_4.change_password(user_id, "pw-v1-12345", "pw-v2-12345")
        await auth_history_4.change_password(user_id, "pw-v2-12345", "pw-v3-12345")

        # pw-v1 is 3 back; still in the window of 4.
        with pytest.raises(AuthError) as exc_info:
            await auth_history_4.change_password(user_id, "pw-v3-12345", "pw-v1-12345")
        assert exc_info.value.code == "password_reused"

    async def test_reuse_outside_window_allowed(self, auth_history_4: AuthFort):
        email, user_id = await _create_user(auth_history_4, password="pw-old0-9999")
        # Cycle through 4 new distinct passwords so the original falls off.
        await auth_history_4.change_password(user_id, "pw-old0-9999", "pw-new1-9999")
        await auth_history_4.change_password(user_id, "pw-new1-9999", "pw-new2-9999")
        await auth_history_4.change_password(user_id, "pw-new2-9999", "pw-new3-9999")
        await auth_history_4.change_password(user_id, "pw-new3-9999", "pw-new4-9999")

        # pw-old0 should now be outside the last-4 window (current + 3 previous).
        await auth_history_4.change_password(user_id, "pw-new4-9999", "pw-old0-9999")

    async def test_history_pruned_to_count(self, auth_history_4: AuthFort):
        email, user_id = await _create_user(auth_history_4, password="pw-0000000000")
        # 6 changes — each distinct.
        pws = [f"pw-aaaaaa{i}" for i in range(6)]
        prev = "pw-0000000000"
        for nxt in pws:
            await auth_history_4.change_password(user_id, prev, nxt)
            prev = nxt

        async with get_session(auth_history_4.session_factory) as session:
            rows = await password_history_repo.get_recent_password_hashes(
                session, user_id, limit=100,
            )
        # Keep exactly 4 — the 4 most recent.
        assert len(rows) == 4

    async def test_reset_password_enforces_history(self, auth_history_4: AuthFort):
        email, user_id = await _create_user(auth_history_4, password="pw-reset-a1")
        await auth_history_4.change_password(user_id, "pw-reset-a1", "pw-reset-b2")

        # Forgot-password reset back to the original — should reject.
        token = await auth_history_4.create_password_reset_token(email)
        with pytest.raises(AuthError) as exc_info:
            await auth_history_4.reset_password(token, "pw-reset-a1")
        assert exc_info.value.code == "password_reused"

    async def test_event_emitted_on_reuse(self, auth_history_4: AuthFort):
        events = []
        auth_history_4.add_hook("password_reuse_rejected", lambda e: events.append(e))

        email, user_id = await _create_user(auth_history_4, password="pw-event-a1")
        await auth_history_4.change_password(user_id, "pw-event-a1", "pw-event-b2")
        with pytest.raises(AuthError):
            await auth_history_4.change_password(user_id, "pw-event-b2", "pw-event-a1")

        assert len(events) == 1
        assert events[0].user_id == user_id
