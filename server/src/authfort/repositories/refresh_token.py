"""Refresh token repository — database operations for refresh tokens."""

import uuid

from sqlalchemy import delete as sa_delete, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.refresh_token import RefreshToken


async def create_refresh_token(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    token_hash: str,
    expires_at,
    user_agent: str | None = None,
    ip_address: str | None = None,
    session_id: uuid.UUID | None = None,
) -> RefreshToken:
    """Create a new refresh token record (store the hash, not the raw token).

    Args:
        session_id: Stable session identifier carried across refresh rotations.
            If None (new login), the token's own id is used as the session_id.
    """
    token_id = uuid.uuid4()
    token = RefreshToken(
        id=token_id,
        user_id=user_id,
        token_hash=token_hash,
        session_id=session_id if session_id is not None else token_id,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    session.add(token)
    await session.flush()
    return token


async def get_refresh_token_by_hash(
    session: AsyncSession,
    token_hash: str,
) -> RefreshToken | None:
    """Look up a refresh token by its SHA-256 hash."""
    statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = (await session.execute(statement)).scalars()
    return result.first()


async def get_refresh_token_by_id(
    session: AsyncSession,
    token_id: uuid.UUID,
) -> RefreshToken | None:
    """Look up a refresh token by its primary key ID."""
    statement = select(RefreshToken).where(RefreshToken.id == token_id)
    result = (await session.execute(statement)).scalars()
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
    *,
    exclude: uuid.UUID | None = None,
) -> None:
    """Revoke ALL refresh tokens for a user (nuclear option — used for theft detection).

    Uses atomic SQL UPDATE to avoid race conditions with concurrent token creation.

    Args:
        exclude: If provided, keep all tokens belonging to this session_id alive.
    """
    stmt = sa_update(RefreshToken).where(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False,
    )
    if exclude is not None:
        stmt = stmt.where(RefreshToken.session_id != exclude)
    stmt = stmt.values(revoked=True)
    await session.execute(stmt)
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
    result = (await session.execute(statement)).scalars()
    return list(result.all())


async def delete_expired_refresh_tokens(
    session: AsyncSession,
) -> int:
    """Delete refresh tokens that are expired or revoked.

    Returns the number of deleted rows.
    """
    from datetime import UTC, datetime

    stmt = sa_delete(RefreshToken).where(
        (RefreshToken.revoked == True) | (RefreshToken.expires_at < datetime.now(UTC)),
    )
    result = await session.execute(stmt)
    await session.flush()
    return result.rowcount


async def revoke_session_by_id(
    session: AsyncSession,
    session_id: uuid.UUID,
) -> bool:
    """Revoke all refresh tokens belonging to a session.

    Returns True if at least one active token was revoked, False otherwise.
    """
    stmt = sa_update(RefreshToken).where(
        RefreshToken.session_id == session_id,
        RefreshToken.revoked == False,
    ).values(revoked=True)
    result = await session.execute(stmt)
    await session.flush()
    return result.rowcount > 0
