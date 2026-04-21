"""PasswordHistory repository — stores previous password hashes for reuse prevention."""

import uuid

from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.password_history import PasswordHistory


async def add_password_history(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    password_hash: str,
) -> None:
    """Append a password hash to the user's history."""
    row = PasswordHistory(user_id=user_id, password_hash=password_hash)
    session.add(row)
    await session.flush()


async def get_recent_password_hashes(
    session: AsyncSession,
    user_id: uuid.UUID,
    limit: int,
) -> list[str]:
    """Return the N most recent password hashes for a user, newest first."""
    if limit <= 0:
        return []
    statement = (
        select(PasswordHistory.password_hash)
        .where(PasswordHistory.user_id == user_id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(statement)
    return list(result.scalars().all())


async def prune_password_history(
    session: AsyncSession,
    user_id: uuid.UUID,
    keep: int,
) -> None:
    """Delete all but the `keep` most recent history rows for a user."""
    if keep <= 0:
        # Feature disabled — wipe anything left behind.
        stmt = sa_delete(PasswordHistory).where(PasswordHistory.user_id == user_id)
        await session.execute(stmt)
        await session.flush()
        return

    # Get IDs of rows to keep (N most recent).
    keep_ids_stmt = (
        select(PasswordHistory.id)
        .where(PasswordHistory.user_id == user_id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(keep)
    )
    keep_ids = list((await session.execute(keep_ids_stmt)).scalars().all())
    if not keep_ids:
        return

    stmt = sa_delete(PasswordHistory).where(
        PasswordHistory.user_id == user_id,
        PasswordHistory.id.notin_(keep_ids),
    )
    await session.execute(stmt)
    await session.flush()
