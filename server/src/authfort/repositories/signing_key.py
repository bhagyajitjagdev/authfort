"""Signing key repository — database operations for JWT signing keys."""

import uuid
from datetime import UTC, datetime

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.models.signing_key import SigningKey


async def get_current_signing_key(session: AsyncSession) -> SigningKey | None:
    """Get the current active signing key."""
    statement = select(SigningKey).where(SigningKey.is_current == True)
    result = await session.exec(statement)
    return result.first()


async def get_signing_key_by_kid(session: AsyncSession, kid: str) -> SigningKey | None:
    """Get a signing key by its key ID (kid)."""
    statement = select(SigningKey).where(SigningKey.kid == kid)
    result = await session.exec(statement)
    return result.first()


async def get_all_signing_keys(session: AsyncSession) -> list[SigningKey]:
    """Get all signing keys (for JWKS endpoint)."""
    statement = select(SigningKey).order_by(SigningKey.created_at.desc())
    result = await session.exec(statement)
    return list(result.all())


async def create_signing_key(
    session: AsyncSession,
    *,
    kid: str,
    private_key: str,
    public_key: str,
    algorithm: str,
    is_current: bool = True,
) -> SigningKey:
    """Create a new signing key. If is_current=True, deactivates any existing current key."""
    if is_current:
        current = await get_current_signing_key(session)
        if current is not None:
            current.is_current = False
            session.add(current)

    key = SigningKey(
        kid=kid,
        private_key=private_key,
        public_key=public_key,
        algorithm=algorithm,
        is_current=is_current,
    )
    session.add(key)
    await session.flush()
    await session.refresh(key)
    return key


async def set_expires_at(
    session: AsyncSession, key_id: uuid.UUID, expires_at: datetime,
) -> None:
    """Set the expires_at timestamp on a signing key (used during key rotation)."""
    key = await session.get(SigningKey, key_id)
    if key is not None:
        key.expires_at = expires_at
        session.add(key)
        await session.flush()


async def delete_expired_keys(session: AsyncSession) -> int:
    """Delete all signing keys whose expires_at has passed. Returns count deleted."""
    now = datetime.now(UTC)
    statement = select(SigningKey).where(
        SigningKey.expires_at != None,  # noqa: E711
        SigningKey.expires_at < now,
    )
    result = await session.exec(statement)
    expired_keys = list(result.all())
    for key in expired_keys:
        await session.delete(key)
    if expired_keys:
        await session.flush()
    return len(expired_keys)


async def get_non_expired_signing_keys(session: AsyncSession) -> list[SigningKey]:
    """Get all signing keys that are current or not yet expired (for JWKS endpoint)."""
    now = datetime.now(UTC)
    statement = (
        select(SigningKey)
        .where(
            (SigningKey.expires_at == None) | (SigningKey.expires_at > now)  # noqa: E711
        )
        .order_by(SigningKey.created_at.desc())
    )
    result = await session.exec(statement)
    return list(result.all())
