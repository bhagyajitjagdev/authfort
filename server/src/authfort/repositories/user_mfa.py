"""UserMFA repository — database operations for TOTP MFA setup."""

import uuid
from datetime import datetime

from sqlalchemy import select
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
