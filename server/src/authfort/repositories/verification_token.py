"""Verification token repository — database operations for email verify and password reset tokens."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.models.verification_token import VerificationToken


async def create_verification_token(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    token_hash: str,
    type: str,
    expires_at,
) -> VerificationToken:
    """Create a verification token (email verify or password reset)."""
    token = VerificationToken(
        user_id=user_id,
        token_hash=token_hash,
        type=type,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()
    await session.refresh(token)
    return token


async def get_verification_token_by_hash(
    session: AsyncSession,
    token_hash: str,
) -> VerificationToken | None:
    """Look up a verification token by its SHA-256 hash."""
    statement = select(VerificationToken).where(
        VerificationToken.token_hash == token_hash,
    )
    result = await session.exec(statement)
    return result.first()


async def delete_verification_token(
    session: AsyncSession,
    token_id: uuid.UUID,
) -> None:
    """Delete a verification token (after use)."""
    token = await session.get(VerificationToken, token_id)
    if token is not None:
        await session.delete(token)
        await session.flush()


async def delete_verification_tokens_by_user_and_type(
    session: AsyncSession,
    user_id: uuid.UUID,
    type: str,
) -> None:
    """Delete all verification tokens for a user with a given type."""
    statement = select(VerificationToken).where(
        VerificationToken.user_id == user_id,
        VerificationToken.type == type,
    )
    result = await session.exec(statement)
    for token in result.all():
        await session.delete(token)
    await session.flush()
