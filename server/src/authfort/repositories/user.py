"""User repository — database operations for users."""

import uuid

from sqlalchemy import delete as sa_delete, func, or_, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.models.account import Account
from authfort.models.refresh_token import RefreshToken
from authfort.models.user import User
from authfort.models.user_role import UserRole
from authfort.models.verification_token import VerificationToken
from authfort.utils import utc_now


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
    deleted: bool = False,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> tuple[list[User], int]:
    """Paginated user list with filtering.

    Returns (users, total_count) where total_count is the pre-pagination count.

    By default, anonymized / soft-deleted users are excluded. Pass
    ``deleted=True`` to include them as well.
    """
    if sort_by not in _SORT_COLUMNS:
        raise ValueError(
            f"Invalid sort_by '{sort_by}'. Must be one of: {', '.join(sorted(_SORT_COLUMNS))}"
        )

    base = select(User)
    if not deleted:
        base = base.where(User.is_deleted == False)  # noqa: E712
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
    deleted: bool = False,
) -> int:
    """Count users with optional filters.

    Anonymized / soft-deleted users are excluded unless ``deleted=True``.
    """
    base = select(User)
    if not deleted:
        base = base.where(User.is_deleted == False)  # noqa: E712
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


async def _purge_user_related(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Delete every record related to a user (application-level cascade).

    Shared by both hard delete and anonymization. MFA, backup codes, and
    password history are deleted explicitly here rather than relying on a DB
    ``ON DELETE CASCADE`` — anonymization keeps the user row, so the cascade
    would never fire.
    """
    from authfort.repositories import mfa_backup_code as backup_code_repo
    from authfort.repositories import password_history as password_history_repo
    from authfort.repositories import user_mfa as user_mfa_repo

    # Roles
    await session.execute(
        sa_delete(UserRole).where(UserRole.user_id == user_id)
    )
    # Clear self-referential FK on refresh tokens, then delete them
    await session.execute(
        sa_update(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .values(replaced_by=None)
    )
    await session.execute(
        sa_delete(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    # OAuth / email accounts
    await session.execute(
        sa_delete(Account).where(Account.user_id == user_id)
    )
    # Verification tokens (email verify, magic link, OTP, password reset)
    await session.execute(
        sa_delete(VerificationToken).where(VerificationToken.user_id == user_id)
    )
    # MFA secret, backup codes, password history
    await user_mfa_repo.delete_user_mfa_for_user(session, user_id)
    await backup_code_repo.delete_backup_codes_for_user(session, user_id)
    await password_history_repo.prune_password_history(session, user_id, keep=0)
    await session.flush()


async def delete_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Hard-delete a user and all related records (application-level cascade).

    Removes the ``authfort_users`` row entirely. Use ``anonymize_user`` for the
    soft-delete / right-to-erasure path that retains the row + id.

    Raises ValueError if user not found.
    """
    user = await session.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found")

    await _purge_user_related(session, user_id)
    await session.delete(user)
    await session.flush()


async def anonymize_user(session: AsyncSession, user_id: uuid.UUID) -> bool:
    """Anonymize + soft-delete a user, keeping the row and its id intact.

    Scrubs PII, kills credentials, revokes all access, deletes related records
    (sessions, accounts, MFA, etc.), and flags the account deleted — but leaves
    the ``authfort_users`` row so external foreign keys stay valid. The original
    email is freed (rewritten to a unique placeholder) for future re-signup.

    Returns True if the user was anonymized, or False if it was already deleted
    (idempotent no-op). Raises ValueError if the user does not exist.
    """
    user = await session.get(User, user_id)
    if user is None:
        raise ValueError(f"User {user_id} not found")
    if user.is_deleted:
        return False

    await _purge_user_related(session, user_id)

    # Scrub PII. The placeholder email is unique (user_id is a UUID), satisfies
    # the unique constraint, and frees the original address for re-registration.
    user.name = "Deleted user"
    user.avatar_url = None
    user.phone = None
    user.email = f"deleted+{user_id}@deleted.invalid"
    # Kill credentials + revoke live access tokens.
    user.password_hash = None
    user.token_version = user.token_version + 1
    # Flag deleted.
    user.is_deleted = True
    user.deleted_at = utc_now()

    session.add(user)
    await session.flush()
    return True
