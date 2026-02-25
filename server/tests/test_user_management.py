"""Tests for admin user management — list, get, delete, count."""

import uuid

import pytest
import pytest_asyncio

from authfort import AuthFort, AuthError, ListUsersResponse, UserDeleted

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _email(tag: str) -> str:
    return f"mgmt-{tag}-{uuid.uuid4().hex[:6]}@example.com"


async def _create_user(auth: AuthFort, email: str, *, name: str | None = None):
    """Create a user and return the AuthResponse."""
    return await auth.create_user(email, "Password1!", name=name)


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------

class TestListUsers:
    async def test_empty(self, auth: AuthFort):
        # Use a query that won't match any existing users
        result = await auth.list_users(query="zzz-no-match-ever-zzz")
        assert isinstance(result, ListUsersResponse)
        assert result.users == []
        assert result.total == 0
        assert result.limit == 50
        assert result.offset == 0

    async def test_returns_all(self, auth: AuthFort):
        emails = [_email("all") for _ in range(3)]
        for e in emails:
            await _create_user(auth, e)

        result = await auth.list_users()
        returned_emails = {u.email for u in result.users}
        for e in emails:
            assert e in returned_emails
        assert result.total >= 3

    async def test_pagination(self, auth: AuthFort):
        emails = sorted([_email("page") for _ in range(3)])
        for e in emails:
            await _create_user(auth, e)

        # Get total first to verify pagination math
        full = await auth.list_users(sort_by="email", sort_order="asc")
        total = full.total

        # Page 1 (limit=2)
        page1 = await auth.list_users(limit=2, offset=0, sort_by="email", sort_order="asc")
        assert len(page1.users) == 2
        assert page1.total == total

        # Page 2 (offset=2)
        page2 = await auth.list_users(limit=2, offset=total - 1, sort_by="email", sort_order="asc")
        assert len(page2.users) == 1
        assert page2.total == total

    async def test_query_email(self, auth: AuthFort):
        unique = uuid.uuid4().hex[:8]
        email = f"findme-{unique}@search.com"
        await _create_user(auth, email)
        await _create_user(auth, _email("noise"))

        result = await auth.list_users(query=unique)
        assert result.total == 1
        assert result.users[0].email == email

    async def test_query_name(self, auth: AuthFort):
        unique = uuid.uuid4().hex[:8]
        email = _email("nameq")
        await _create_user(auth, email, name=f"SpecialName-{unique}")

        result = await auth.list_users(query=f"SpecialName-{unique}")
        assert result.total == 1
        assert result.users[0].name == f"SpecialName-{unique}"

    async def test_query_case_insensitive(self, auth: AuthFort):
        unique = uuid.uuid4().hex[:8]
        email = f"lowercase-{unique}@test.com"
        await _create_user(auth, email)

        result = await auth.list_users(query=f"LOWERCASE-{unique}")
        assert result.total == 1
        assert result.users[0].email == email

    async def test_filter_banned(self, auth: AuthFort):
        email = _email("ban")
        resp = await _create_user(auth, email)
        await auth.ban_user(resp.user.id)

        result = await auth.list_users(banned=True)
        banned_emails = {u.email for u in result.users}
        assert email in banned_emails

        result_not_banned = await auth.list_users(banned=False)
        not_banned_emails = {u.email for u in result_not_banned.users}
        assert email not in not_banned_emails

    async def test_filter_role(self, auth: AuthFort):
        email = _email("role")
        resp = await _create_user(auth, email)
        await auth.add_role(resp.user.id, "manager")

        result = await auth.list_users(role="manager")
        role_emails = {u.email for u in result.users}
        assert email in role_emails

    async def test_combined_filters(self, auth: AuthFort):
        unique = uuid.uuid4().hex[:8]
        email = f"combo-{unique}@test.com"
        resp = await _create_user(auth, email)
        await auth.ban_user(resp.user.id)
        await auth.add_role(resp.user.id, "editor")

        result = await auth.list_users(query=unique, banned=True, role="editor")
        assert result.total == 1
        assert result.users[0].email == email

    async def test_sort_email_asc(self, auth: AuthFort):
        prefix = uuid.uuid4().hex[:6]
        emails = [f"{prefix}-a@test.com", f"{prefix}-b@test.com", f"{prefix}-c@test.com"]
        for e in emails:
            await _create_user(auth, e)

        result = await auth.list_users(query=prefix, sort_by="email", sort_order="asc")
        result_emails = [u.email for u in result.users]
        assert result_emails == sorted(result_emails)

    async def test_sort_created_at_desc(self, auth: AuthFort):
        emails = [_email("sort") for _ in range(3)]
        for e in emails:
            await _create_user(auth, e)

        result = await auth.list_users(sort_by="created_at", sort_order="desc")
        timestamps = [u.created_at for u in result.users]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_invalid_sort_by(self, auth: AuthFort):
        with pytest.raises(ValueError, match="Invalid sort_by"):
            await auth.list_users(sort_by="nonexistent")


# ---------------------------------------------------------------------------
# get_user_count
# ---------------------------------------------------------------------------

class TestGetUserCount:
    async def test_basic(self, auth: AuthFort):
        before = await auth.get_user_count()
        await _create_user(auth, _email("cnt"))
        after = await auth.get_user_count()
        assert after == before + 1

    async def test_with_filters(self, auth: AuthFort):
        unique = uuid.uuid4().hex[:8]
        email = f"countfilt-{unique}@test.com"
        resp = await _create_user(auth, email)
        await auth.ban_user(resp.user.id)

        total = await auth.get_user_count()
        banned_count = await auth.get_user_count(banned=True)
        query_count = await auth.get_user_count(query=unique)

        assert banned_count >= 1
        assert query_count == 1
        assert total >= banned_count


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------

class TestGetUser:
    async def test_existing(self, auth: AuthFort):
        email = _email("get")
        resp = await _create_user(auth, email, name="GetTest")

        user = await auth.get_user(resp.user.id)
        assert user.id == resp.user.id
        assert user.email == email
        assert user.name == "GetTest"
        assert user.email_verified is False

    async def test_includes_roles(self, auth: AuthFort):
        email = _email("getrole")
        resp = await _create_user(auth, email)
        await auth.add_role(resp.user.id, "admin")
        await auth.add_role(resp.user.id, "editor")

        user = await auth.get_user(resp.user.id)
        assert "admin" in user.roles
        assert "editor" in user.roles

    async def test_nonexistent(self, auth: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth.get_user(uuid.uuid4())
        assert exc_info.value.code == "user_not_found"


# ---------------------------------------------------------------------------
# delete_user
# ---------------------------------------------------------------------------

class TestDeleteUser:
    async def test_basic(self, auth: AuthFort):
        email = _email("del")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        await auth.delete_user(user_id)

        with pytest.raises(AuthError):
            await auth.get_user(user_id)

    async def test_with_sessions(self, auth: AuthFort):
        email = _email("delsess")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        # Login creates a refresh token / session
        await auth.login(email, "Password1!")

        await auth.delete_user(user_id)
        with pytest.raises(AuthError):
            await auth.get_user(user_id)

    async def test_with_oauth_accounts(self, auth: AuthFort):
        """User with an OAuth account can be deleted."""
        from authfort.repositories import account as account_repo

        email = _email("deloauth")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        # Manually create an OAuth account record
        async with auth.get_session() as session:
            await account_repo.create_account(
                session,
                user_id=user_id,
                provider="google",
                provider_account_id="google-123",
            )

        await auth.delete_user(user_id)
        with pytest.raises(AuthError):
            await auth.get_user(user_id)

    async def test_with_roles(self, auth: AuthFort):
        email = _email("delrole")
        resp = await _create_user(auth, email)
        user_id = resp.user.id
        await auth.add_role(user_id, "admin")

        await auth.delete_user(user_id)
        with pytest.raises(AuthError):
            await auth.get_user(user_id)

    async def test_fires_event(self, auth: AuthFort):
        email = _email("delevt")
        resp = await _create_user(auth, email)
        user_id = resp.user.id

        events_received = []

        @auth.on("user_deleted")
        async def on_deleted(event):
            events_received.append(event)

        await auth.delete_user(user_id)

        assert len(events_received) == 1
        assert isinstance(events_received[0], UserDeleted)
        assert events_received[0].user_id == user_id
        assert events_received[0].email == email

    async def test_nonexistent(self, auth: AuthFort):
        with pytest.raises(ValueError, match="not found"):
            await auth.delete_user(uuid.uuid4())

    async def test_cannot_login_after(self, auth: AuthFort):
        email = _email("dellogin")
        resp = await _create_user(auth, email)
        await auth.delete_user(resp.user.id)

        with pytest.raises(AuthError):
            await auth.login(email, "Password1!")

    async def test_count_decreases(self, auth: AuthFort):
        email = _email("delcnt")
        resp = await _create_user(auth, email)

        before = await auth.get_user_count()
        await auth.delete_user(resp.user.id)
        after = await auth.get_user_count()

        assert after == before - 1
