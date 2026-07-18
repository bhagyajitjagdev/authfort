"""UserMFA repository — database operations for TOTP MFA setup."""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.user_mfa import UserMFA
from authfort.utils import utc_now


async def get_user_mfa(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> UserMFA | None:
    """Get the MFA record for a user, or None if MFA has never been set up."""
    statement = select(UserMFA).where(UserMFA.user_id == user_id)
    result = (await session.execute(statement)).scalars()
    return result.first()


async def create_user_mfa(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    totp_secret: str,
) -> UserMFA:
    """Create a new MFA record for a user (enabled=False until confirmed)."""
    mfa = UserMFA(user_id=user_id, totp_secret=totp_secret)
    session.add(mfa)
    await session.flush()
    await session.refresh(mfa)
    return mfa


async def enable_user_mfa(
    session: AsyncSession,
    user_mfa: UserMFA,
    *,
    code: str,
) -> None:
    """Mark MFA as enabled and record the first used code for replay protection."""
    now = utc_now()
    user_mfa.enabled = True
    user_mfa.enabled_at = now
    user_mfa.last_used_at = now
    user_mfa.last_used_code = code
    await session.flush()


async def disable_user_mfa(
    session: AsyncSession,
    user_mfa: UserMFA,
) -> None:
    """Delete the MFA record entirely (MFA is now disabled for this user)."""
    await session.delete(user_mfa)
    await session.flush()


async def delete_user_mfa_for_user(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> None:
    """Delete a user's MFA record by user_id (no-op if none exists).

    Set-based delete used by account anonymization / deletion, where the row
    is removed explicitly rather than relying on a DB cascade.
    """
    stmt = sa_delete(UserMFA).where(UserMFA.user_id == user_id)
    await session.execute(stmt)
    await session.flush()


async def update_last_used(
    session: AsyncSession,
    user_mfa: UserMFA,
    *,
    code: str,
    used_at: datetime,
) -> None:
    """Update last used code + timestamp after a successful TOTP verification."""
    user_mfa.last_used_at = used_at
    user_mfa.last_used_code = code
    await session.flush()


async def record_failed_attempt(
    session: AsyncSession,
    user_mfa: UserMFA,
    *,
    max_attempts: int,
    lockout_seconds: int,
    now: datetime,
) -> bool:
    """Increment the failed-attempt counter; lock if the threshold is crossed.

    Returns True if this call caused a transition into the locked state (so the
    caller can emit a single mfa_locked event), False otherwise.
    """
    user_mfa.failed_attempts += 1
    newly_locked = False
    if max_attempts > 0 and user_mfa.failed_attempts >= max_attempts:
        user_mfa.locked_until = now + timedelta(seconds=lockout_seconds)
        newly_locked = True
    await session.flush()
    return newly_locked


async def reset_failed_attempts(
    session: AsyncSession,
    user_mfa: UserMFA,
) -> None:
    """Clear the failed-attempt counter and any lock (on successful verify)."""
    user_mfa.failed_attempts = 0
    user_mfa.locked_until = None
    await session.flush()
