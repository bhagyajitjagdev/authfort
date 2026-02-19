"""User repository — database operations for users."""

import uuid

from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.user import User


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Get a user by their ID."""
    return await session.get(User, user_id)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Get a user by their email address."""
    statement = select(User).where(User.email == email)
    result = (await session.execute(statement)).scalars()
    return result.first()


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    password_hash: str | None = None,
    name: str | None = None,
    email_verified: bool = False,
) -> User:
    """Create a new user."""
    user = User(
        email=email,
        password_hash=password_hash,
        name=name,
        email_verified=email_verified,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def update_user(
    session: AsyncSession,
    user: User,
    **kwargs,
) -> User:
    """Update user fields."""
    for key, value in kwargs.items():
        if hasattr(user, key):
            setattr(user, key, value)
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def ban_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Ban a user — sets banned=True, bumps token_version, revokes all refresh tokens."""
    from authfort.repositories import refresh_token as refresh_token_repo

    stmt = sa_update(User).where(User.id == user_id).values(
        banned=True, token_version=User.token_version + 1,
    )
    result = await session.execute(stmt)
    if result.rowcount == 0:
        raise ValueError(f"User {user_id} not found")
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user_id)
    await session.flush()


async def unban_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Unban a user — sets banned=False."""
    user = await session.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found")
    user.banned = False
    session.add(user)
    await session.flush()


async def bump_token_version(session: AsyncSession, user_id: uuid.UUID) -> int:
    """Bump the user's token_version for immediate invalidation. Returns the new version.

    Uses atomic SQL increment to avoid race conditions under concurrent requests.
    """
    stmt = sa_update(User).where(User.id == user_id).values(
        token_version=User.token_version + 1,
    )
    result = await session.execute(stmt)
    if result.rowcount == 0:
        raise ValueError(f"User {user_id} not found")
    await session.flush()
    user = await session.get(User, user_id)
    await session.refresh(user)
    return user.token_version
