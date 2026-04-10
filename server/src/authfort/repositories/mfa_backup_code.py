"""MFABackupCode repository — database operations for MFA backup codes."""

import uuid

from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.mfa_backup_code import MFABackupCode
from authfort.utils import utc_now


async def create_backup_codes(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    code_hashes: list[str],
) -> None:
    """Bulk-insert backup codes for a user (stores SHA-256 hashes only)."""
    codes = [MFABackupCode(user_id=user_id, code_hash=h) for h in code_hashes]
    session.add_all(codes)
    await session.flush()


async def get_unused_backup_codes(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> list[MFABackupCode]:
    """Return all unused backup codes for a user."""
    statement = select(MFABackupCode).where(
        MFABackupCode.user_id == user_id,
        MFABackupCode.used == False,  # noqa: E712
    )
    result = (await session.execute(statement)).scalars()
    return list(result.all())


async def mark_backup_code_used(
    session: AsyncSession,
    backup_code: MFABackupCode,
) -> None:
    """Mark a backup code as used."""
    backup_code.used = True
    backup_code.used_at = utc_now()
    await session.flush()


async def delete_backup_codes_for_user(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> None:
    """Delete all backup codes for a user (used when disabling MFA or regenerating)."""
    stmt = sa_delete(MFABackupCode).where(MFABackupCode.user_id == user_id)
    await session.execute(stmt)
    await session.flush()


async def count_remaining(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> int:
    """Count unused backup codes remaining for a user."""
    statement = select(func.count()).where(
        MFABackupCode.user_id == user_id,
        MFABackupCode.used == False,  # noqa: E712
    )
    result = await session.execute(statement)
    return result.scalar_one()
