"""Tests for the internal migration system."""

import os
import tempfile
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import inspect, text

from authfort import AuthFort, CookieConfig

AUTHFORT_TABLES = [
    "authfort_users",
    "authfort_accounts",
    "authfort_refresh_tokens",
    "authfort_user_roles",
    "authfort_signing_keys",
    "authfort_verification_tokens",
]


@pytest_asyncio.fixture
async def fresh_auth():
    """AuthFort instance with a brand-new SQLite database."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    url = f"sqlite+aiosqlite:///{tmp.name}"
    instance = AuthFort(database_url=url, cookie=CookieConfig(secure=False))
    yield instance
    await instance.dispose()
    os.remove(tmp.name)


@pytest.mark.asyncio
class TestMigrate:
    async def test_migrate_fresh_db(self, fresh_auth: AuthFort):
        """All 6 authfort_* tables are created on a fresh database."""
        await fresh_auth.migrate()

        async with fresh_auth._engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )

        for table in AUTHFORT_TABLES:
            assert table in tables, f"Missing table: {table}"

    async def test_migrate_idempotent(self, fresh_auth: AuthFort):
        """Running migrate() twice causes no errors."""
        await fresh_auth.migrate()
        await fresh_auth.migrate()  # Should be a no-op

    async def test_version_table_created(self, fresh_auth: AuthFort):
        """The authfort_alembic_version tracking table exists after migrate."""
        await fresh_auth.migrate()

        async with fresh_auth._engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )

        assert "authfort_alembic_version" in tables

    async def test_migrate_then_crud(self, fresh_auth: AuthFort):
        """Schema created by migrate() supports full auth operations."""
        await fresh_auth.migrate()

        email = f"test-{uuid.uuid4().hex[:8]}@example.com"
        result = await fresh_auth.create_user(email, "password123", name="Test")
        assert result.user.email == email

        login_result = await fresh_auth.login(email, "password123")
        assert login_result.user.email == email


