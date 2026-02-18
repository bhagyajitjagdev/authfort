"""Account repository — database operations for OAuth/provider accounts."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.models.account import Account


async def create_account(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    provider: str,
    provider_account_id: str | None = None,
    access_token: str | None = None,
    refresh_token: str | None = None,
) -> Account:
    """Create an account linking a provider to a user."""
    account = Account(
        user_id=user_id,
        provider=provider,
        provider_account_id=provider_account_id,
        access_token=access_token,
        refresh_token=refresh_token,
    )
    session.add(account)
    await session.flush()
    await session.refresh(account)
    return account


async def get_account_by_provider(
    session: AsyncSession,
    provider: str,
    provider_account_id: str,
) -> Account | None:
    """Get an account by provider and provider account ID."""
    statement = select(Account).where(
        Account.provider == provider,
        Account.provider_account_id == provider_account_id,
    )
    result = await session.exec(statement)
    return result.first()


async def get_accounts_by_user(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> list[Account]:
    """Get all accounts linked to a user."""
    statement = select(Account).where(Account.user_id == user_id)
    result = await session.exec(statement)
    return list(result.all())
