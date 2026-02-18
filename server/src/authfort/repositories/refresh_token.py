"""Refresh token repository — database operations for refresh tokens."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.models.refresh_token import RefreshToken


async def create_refresh_token(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    token_hash: str,
    expires_at,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> RefreshToken:
    """Create a new refresh token record (store the hash, not the raw token)."""
    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    session.add(token)
    await session.flush()
    await session.refresh(token)
    return token


async def get_refresh_token_by_hash(
    session: AsyncSession,
    token_hash: str,
) -> RefreshToken | None:
    """Look up a refresh token by its SHA-256 hash."""
    statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = await session.exec(statement)
    return result.first()


async def revoke_refresh_token(
    session: AsyncSession,
    token: RefreshToken,
    replaced_by: uuid.UUID | None = None,
) -> None:
    """Revoke a refresh token (mark as revoked, optionally link replacement)."""
    token.revoked = True
    if replaced_by is not None:
        token.replaced_by = replaced_by
    session.add(token)
    await session.flush()


async def revoke_all_user_refresh_tokens(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> None:
    """Revoke ALL refresh tokens for a user (nuclear option — used for theft detection)."""
    statement = select(RefreshToken).where(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False,
    )
    result = await session.exec(statement)
    tokens = result.all()
    for token in tokens:
        token.revoked = True
        session.add(token)
    await session.flush()


async def get_sessions_by_user(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    active_only: bool = False,
) -> list[RefreshToken]:
    """List all refresh tokens (sessions) for a user.

    Args:
        user_id: The user's UUID.
        active_only: If True, only return non-revoked and non-expired sessions.
    """
    statement = select(RefreshToken).where(RefreshToken.user_id == user_id)
    if active_only:
        from datetime import UTC, datetime

        statement = statement.where(
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(UTC),
        )
    statement = statement.order_by(RefreshToken.created_at.desc())
    result = await session.exec(statement)
    return list(result.all())


async def revoke_session_by_id(
    session: AsyncSession,
    session_id: uuid.UUID,
) -> bool:
    """Revoke a specific session (refresh token) by its ID.

    Returns True if the session was found and revoked, False if not found or already revoked.
    """
    statement = select(RefreshToken).where(RefreshToken.id == session_id)
    result = await session.exec(statement)
    token = result.first()
    if token is None or token.revoked:
        return False
    token.revoked = True
    session.add(token)
    await session.flush()
    return True
