"""User repository — database operations for users."""

import uuid

from sqlalchemy import delete as sa_delete, func, or_, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.account import Account
from authfort.models.refresh_token import RefreshToken
from authfort.models.user import User
from authfort.models.user_role import UserRole
from authfort.models.verification_token import VerificationToken


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Get a user by their ID."""
    return await session.get(User, user_id)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Get a user by their email address."""
    statement = select(User).where(User.email == email)
    result = (await session.execute(statement)).scalars()
    return result.first()


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    password_hash: str | None = None,
    name: str | None = None,
    avatar_url: str | None = None,
    phone: str | None = None,
    email_verified: bool = False,
) -> User:
    """Create a new user."""
    user = User(
        email=email,
        password_hash=password_hash,
        name=name,
        avatar_url=avatar_url,
        phone=phone,
        email_verified=email_verified,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def update_user(
    session: AsyncSession,
    user: User,
    **kwargs,
) -> User:
    """Update user fields."""
    for key, value in kwargs.items():
        if hasattr(user, key):
            setattr(user, key, value)
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def ban_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Ban a user — sets banned=True, bumps token_version, revokes all refresh tokens."""
    from authfort.repositories import refresh_token as refresh_token_repo

    stmt = sa_update(User).where(User.id == user_id).values(
        banned=True, token_version=User.token_version + 1,
    )
    result = await session.execute(stmt)
    if result.rowcount == 0:
        raise ValueError(f"User {user_id} not found")
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user_id)
    await session.flush()


async def unban_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Unban a user — sets banned=False."""
    user = await session.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found")
    user.banned = False
    session.add(user)
    await session.flush()


async def bump_token_version(session: AsyncSession, user_id: uuid.UUID) -> int:
    """Bump the user's token_version for immediate invalidation. Returns the new version.

    Uses atomic SQL increment to avoid race conditions under concurrent requests.
    """
    stmt = sa_update(User).where(User.id == user_id).values(
        token_version=User.token_version + 1,
    )
    result = await session.execute(stmt)
    if result.rowcount == 0:
        raise ValueError(f"User {user_id} not found")
    await session.flush()
    user = await session.get(User, user_id)
    await session.refresh(user)
    return user.token_version


_SORT_COLUMNS = {
    "created_at": User.created_at,
    "email": User.email,
    "name": User.name,
}


async def list_users(
    session: AsyncSession,
    *,
    limit: int = 50,
    offset: int = 0,
    query: str | None = None,
    banned: bool | None = None,
    role: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> tuple[list[User], int]:
    """Paginated user list with filtering.

    Returns (users, total_count) where total_count is the pre-pagination count.
    """
    if sort_by not in _SORT_COLUMNS:
        raise ValueError(
            f"Invalid sort_by '{sort_by}'. Must be one of: {', '.join(sorted(_SORT_COLUMNS))}"
        )

    base = select(User)
    if query is not None:
        pattern = f"%{query}%"
        base = base.where(
            or_(User.email.ilike(pattern), User.name.ilike(pattern))
        )
    if banned is not None:
        base = base.where(User.banned == banned)
    if role is not None:
        base = base.where(
            User.id.in_(select(UserRole.user_id).where(UserRole.role == role))
        )

    # Total count (pre-pagination)
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await session.execute(count_stmt)).scalar_one()

    # Paginated results
    col = _SORT_COLUMNS[sort_by]
    order = col.asc() if sort_order == "asc" else col.desc()
    stmt = base.order_by(order).limit(limit).offset(offset)
    users = list((await session.execute(stmt)).scalars().all())

    return users, total


async def get_user_count(
    session: AsyncSession,
    *,
    query: str | None = None,
    banned: bool | None = None,
    role: str | None = None,
) -> int:
    """Count users with optional filters."""
    base = select(User)
    if query is not None:
        pattern = f"%{query}%"
        base = base.where(
            or_(User.email.ilike(pattern), User.name.ilike(pattern))
        )
    if banned is not None:
        base = base.where(User.banned == banned)
    if role is not None:
        base = base.where(
            User.id.in_(select(UserRole.user_id).where(UserRole.role == role))
        )
    count_stmt = select(func.count()).select_from(base.subquery())
    return (await session.execute(count_stmt)).scalar_one()


async def delete_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Delete a user and all related records (application-level cascade).

    Raises ValueError if user not found.
    """
    user = await session.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found")

    # 1. Delete user roles
    await session.execute(
        sa_delete(UserRole).where(UserRole.user_id == user_id)
    )
    # 2. Clear self-referential FK on refresh tokens
    await session.execute(
        sa_update(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .values(replaced_by=None)
    )
    # 3. Delete refresh tokens
    await session.execute(
        sa_delete(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    # 4. Delete accounts
    await session.execute(
        sa_delete(Account).where(Account.user_id == user_id)
    )
    # 5. Delete verification tokens
    await session.execute(
        sa_delete(VerificationToken).where(VerificationToken.user_id == user_id)
    )
    # 6. Delete the user
    await session.delete(user)
    await session.flush()
