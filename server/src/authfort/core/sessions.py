"""Core session management — list and revoke user sessions.

Framework-agnostic. Exposes functions for developers to build their own
session management endpoints with whatever guards they need.
"""

from __future__ import annotations

import uuid

from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.core.schemas import SessionResponse
from authfort.repositories import refresh_token as refresh_token_repo


async def get_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    active_only: bool = False,
) -> list[SessionResponse]:
    """List all sessions for a user.

    Args:
        user_id: The user's UUID.
        active_only: If True, only return active (non-revoked, non-expired) sessions.

    Returns:
        List of SessionResponse objects, newest first.
    """
    tokens = await refresh_token_repo.get_sessions_by_user(
        session, user_id, active_only=active_only,
    )
    return [
        SessionResponse(
            id=t.id,
            user_agent=t.user_agent,
            ip_address=t.ip_address,
            created_at=t.created_at,
            expires_at=t.expires_at,
            revoked=t.revoked,
        )
        for t in tokens
    ]


async def revoke_session(
    session: AsyncSession,
    session_id: uuid.UUID,
) -> bool:
    """Revoke a specific session by its ID.

    Returns True if the session was found and revoked, False otherwise.
    """
    return await refresh_token_repo.revoke_session_by_id(session, session_id)


async def revoke_all_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    exclude: uuid.UUID | None = None,
) -> None:
    """Revoke ALL sessions for a user.

    Args:
        exclude: If provided, keep this session alive (e.g. the current session).
    """
    await refresh_token_repo.revoke_all_user_refresh_tokens(
        session, user_id, exclude=exclude,
    )
