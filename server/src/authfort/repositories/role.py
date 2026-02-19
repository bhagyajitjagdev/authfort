"""Role repository — database operations for user roles."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.user_role import UserRole


async def add_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    role: str,
) -> UserRole:
    """Add a role to a user. Silently succeeds if the role already exists."""
    existing = await _get_user_role(session, user_id, role)
    if existing is not None:
        return existing

    user_role = UserRole(user_id=user_id, role=role)
    session.add(user_role)
    await session.flush()
    await session.refresh(user_role)
    return user_role


async def remove_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    role: str,
) -> None:
    """Remove a role from a user. Silently succeeds if the role doesn't exist."""
    existing = await _get_user_role(session, user_id, role)
    if existing is not None:
        await session.delete(existing)
        await session.flush()


async def get_roles(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> list[str]:
    """Get all roles for a user."""
    statement = select(UserRole).where(UserRole.user_id == user_id)
    result = (await session.execute(statement)).scalars()
    return [ur.role for ur in result.all()]


async def has_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    role: str,
) -> bool:
    """Check if a user has a specific role."""
    return await _get_user_role(session, user_id, role) is not None


async def _get_user_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    role: str,
) -> UserRole | None:
    """Internal helper to find a specific user-role pair."""
    statement = select(UserRole).where(
        UserRole.user_id == user_id,
        UserRole.role == role,
    )
    result = (await session.execute(statement)).scalars()
    return result.first()
