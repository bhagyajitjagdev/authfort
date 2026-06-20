"""Tests for anonymize + soft-delete.

``delete_user()`` anonymizes in place by default (keeps the row + id, scrubs PII,
kills credentials/access, flags ``is_deleted``); ``delete_user(hard=True)`` keeps
the legacy full row delete.
"""

import uuid

import pyotp
import pytest

from authfort import AuthFort, AuthError, UserDeleted

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _email(tag: str) -> str:
    return f"soft-{tag}-{uuid.uuid4().hex[:6]}@example.com"


async def _create_user(auth: AuthFort, email: str, *, name: str = "Original Name"):
    return await auth.create_user(email, "Password1!", name=name)


async def _get_row(auth: AuthFort, user_id: uuid.UUID):
    """Fetch the raw User row (bypassing the get_user is_deleted guard)."""
    from authfort.repositories import user as user_repo

    async with auth.get_session() as session:
        return await user_repo.get_user_by_id(session, user_id)


async def _enable_mfa(auth: AuthFort, user_id: uuid.UUID) -> None:
    setup = await auth.enable_mfa_init(user_id)
    await auth.enable_mfa_confirm(user_id, pyotp.TOTP(setup.secret).now())


# ---------------------------------------------------------------------------
# Anonymize (default delete_user) — acceptance criterion #1
# ---------------------------------------------------------------------------

class TestAnonymize:
    async def test_row_retained_and_anonymized(self, auth: AuthFort):
        email = _email("anon")
        resp = await _create_user(auth, email, name="Jane Doe")
        user_id = resp.user.id

        # Give the account a session and MFA so we can prove they're purged.
        await auth.login(email, "Password1!")
        await _enable_mfa(auth, user_id)

        await auth.delete_user(user_id)

        row = await _get_row(auth, user_id)
        assert row is not None, "row must be retained"
        assert row.id == user_id, "id must be unchanged"
        # PII scrubbed
        assert row.name == "Deleted user"
        assert row.avatar_url is None
        assert row.phone is None
        assert row.email == f"deleted+{user_id}@deleted.invalid"
        assert row.email != email
        # Credentials killed
        assert row.password_hash is None
        # Flags set
        assert row.is_deleted is True
        assert row.deleted_at is not None

    async def test_mfa_and_sessions_purged(self, auth: AuthFort):
        from authfort.repositories import mfa_backup_code as backup_code_repo
        from authfort.repositories import user_mfa as user_mfa_repo

        email = _email("purge")
        resp = await _create_user(auth, email)
        user_id = resp.user.id
        await auth.login(email, "Password1!")
        await _enable_mfa(auth, user_id)

        await auth.delete_user(user_id)

        assert await auth.get_sessions(user_id) == []
        async with auth.get_session() as session:
            assert await user_mfa_repo.get_user_mfa(session, user_id) is None
            assert await backup_code_repo.count_remaining(session, user_id) == 0

    async def test_email_unique_constraint_holds_across_deletes(self, auth: AuthFort):
        a = await _create_user(auth, _email("uq-a"))
        b = await _create_user(auth, _email("uq-b"))
        await auth.delete_user(a.user.id)
        await auth.delete_user(b.user.id)

        row_a = await _get_row(auth, a.user.id)
        row_b = await _get_row(auth, b.user.id)
        assert row_a.email != row_b.email  # placeholders keyed by id are unique

    async def test_fires_event_with_original_email(self, auth: AuthFort):
        email = _email("evt")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        received: list[UserDeleted] = []

        @auth.on("user_deleted")
        async def on_deleted(event):
            received.append(event)

        await auth.delete_user(user_id)

        assert len(received) == 1
        assert received[0].user_id == user_id
        assert received[0].email == email  # original, captured before scrub

    async def test_idempotent_no_op(self, auth: AuthFort):
        email = _email("idem")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        received: list[UserDeleted] = []

        @auth.on("user_deleted")
        async def on_deleted(event):
            received.append(event)

        await auth.delete_user(user_id)
        await auth.delete_user(user_id)  # already deleted → no-op

        assert len(received) == 1, "second delete must not re-fire the event"
        row = await _get_row(auth, user_id)
        assert row.is_deleted is True

    async def test_nonexistent_raises(self, auth: AuthFort):
        with pytest.raises(ValueError, match="not found"):
            await auth.delete_user(uuid.uuid4())


# ---------------------------------------------------------------------------
# Access is revoked — acceptance criterion #2
# ---------------------------------------------------------------------------

class TestDeletedAccessRevoked:
    async def test_cannot_login(self, auth: AuthFort):
        email = _email("login")
        resp = await _create_user(auth, email)
        await auth.delete_user(resp.user.id)

        with pytest.raises(AuthError):
            await auth.login(email, "Password1!")

    async def test_cannot_refresh(self, auth: AuthFort):
        email = _email("refresh")
        resp = await _create_user(auth, email)
        login = await auth.login(email, "Password1!")
        refresh_token = login.tokens.refresh_token

        await auth.delete_user(resp.user.id)

        with pytest.raises(AuthError):
            await auth.refresh(refresh_token)

    async def test_password_reset_not_issued(self, auth: AuthFort):
        email = _email("reset")
        resp = await _create_user(auth, email)
        await auth.delete_user(resp.user.id)

        # Original email no longer maps to a usable account.
        assert await auth.create_password_reset_token(email) is None

    async def test_email_verification_not_issued(self, auth: AuthFort):
        # Hits the is_deleted guard directly (lookup is by user_id).
        email = _email("verify")
        resp = await _create_user(auth, email)
        user_id = resp.user.id
        await auth.delete_user(user_id)

        assert await auth.create_email_verification_token(user_id) is None

    async def test_magic_link_does_not_resurrect(self, auth: AuthFort):
        # Default config disallows passwordless signup, so the freed email
        # yields no token rather than reviving the dead account.
        email = _email("magic")
        resp = await _create_user(auth, email)
        await auth.delete_user(resp.user.id)

        assert await auth.create_magic_link_token(email) is None

    async def test_otp_does_not_resurrect(self, auth: AuthFort):
        email = _email("otp")
        resp = await _create_user(auth, email)
        await auth.delete_user(resp.user.id)

        assert await auth.create_email_otp(email) is None


# ---------------------------------------------------------------------------
# List / read filtering — acceptance criterion #3
# ---------------------------------------------------------------------------

class TestListAndRead:
    async def test_list_excludes_deleted_by_default(self, auth: AuthFort):
        keep = await _create_user(auth, _email("keep"))
        gone = await _create_user(auth, _email("gone"))
        await auth.delete_user(gone.user.id)

        result = await auth.list_users(limit=100)
        ids = {u.id for u in result.users}
        assert keep.user.id in ids
        assert gone.user.id not in ids

    async def test_list_include_deleted(self, auth: AuthFort):
        gone = await _create_user(auth, _email("incl"))
        await auth.delete_user(gone.user.id)

        result = await auth.list_users(limit=100, deleted=True)
        ids = {u.id for u in result.users}
        assert gone.user.id in ids

    async def test_count_excludes_deleted_by_default(self, auth: AuthFort):
        resp = await _create_user(auth, _email("cnt"))
        before = await auth.get_user_count()
        before_incl = await auth.get_user_count(deleted=True)

        await auth.delete_user(resp.user.id)

        assert await auth.get_user_count() == before - 1
        assert await auth.get_user_count(deleted=True) == before_incl

    async def test_get_user_404_for_deleted(self, auth: AuthFort):
        resp = await _create_user(auth, _email("get404"))
        await auth.delete_user(resp.user.id)

        with pytest.raises(AuthError):
            await auth.get_user(resp.user.id)

    async def test_get_user_with_deleted_flag_returns_record(self, auth: AuthFort):
        resp = await _create_user(auth, _email("getincl"))
        user_id = resp.user.id
        await auth.delete_user(user_id)

        record = await auth.get_user(user_id, deleted=True)
        assert record.id == user_id
        assert record.is_deleted is True
        assert record.deleted_at is not None
        assert record.email == f"deleted+{user_id}@deleted.invalid"


# ---------------------------------------------------------------------------
# Email reuse — acceptance criterion #4
# ---------------------------------------------------------------------------

class TestEmailReuse:
    async def test_original_email_registers_fresh_user(self, auth: AuthFort):
        email = _email("reuse")
        first = await _create_user(auth, email, name="First")
        old_id = first.user.id
        await auth.delete_user(old_id)

        second = await _create_user(auth, email, name="Second")
        assert second.user.id != old_id, "must be a brand-new user"
        assert second.user.email == email

        # The old row stays anonymized and independent.
        old_row = await _get_row(auth, old_id)
        assert old_row.is_deleted is True
        assert old_row.email != email

    async def test_can_login_as_fresh_user(self, auth: AuthFort):
        email = _email("reuse-login")
        first = await _create_user(auth, email)
        await auth.delete_user(first.user.id)

        await _create_user(auth, email)
        # Fresh account logs in normally.
        login = await auth.login(email, "Password1!")
        assert login.user.email == email
        assert login.user.id != first.user.id


# ---------------------------------------------------------------------------
# Hard delete escape hatch — legacy behavior preserved
# ---------------------------------------------------------------------------

class TestHardDelete:
    async def test_hard_removes_row(self, auth: AuthFort):
        resp = await _create_user(auth, _email("hard"))
        user_id = resp.user.id

        await auth.delete_user(user_id, hard=True)

        assert await _get_row(auth, user_id) is None

    async def test_hard_fires_event(self, auth: AuthFort):
        email = _email("hard-evt")
        resp = await _create_user(auth, email)

        received: list[UserDeleted] = []

        @auth.on("user_deleted")
        async def on_deleted(event):
            received.append(event)

        await auth.delete_user(resp.user.id, hard=True)

        assert len(received) == 1
        assert received[0].email == email
