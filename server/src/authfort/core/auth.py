"""Core auth service — signup, login, refresh, logout.

Framework-agnostic business logic. All functions take an AsyncSession and config.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.keys import generate_key_pair, generate_kid
from authfort.core.refresh import generate_refresh_token, hash_refresh_token
from authfort.core.schemas import AuthResponse, AuthTokens, UserResponse
from authfort.core.tokens import create_access_token
from authfort.repositories import account as account_repo
from authfort.repositories import refresh_token as refresh_token_repo
from authfort.repositories import role as role_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo
from authfort.utils.passwords import hash_password, verify_password

if TYPE_CHECKING:
    from authfort.events import EventCollector


class AuthError(Exception):
    """Base auth error with an error code and HTTP status."""

    def __init__(self, message: str, code: str, status_code: int = 400, **extra):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.extra = extra
        super().__init__(message)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(email: str) -> str:
    """Basic email format validation — no dependencies, just a sanity check."""
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise AuthError("Invalid email address", code="invalid_email", status_code=400)
    return email


async def signup(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    password: str,
    name: str | None = None,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Register a new user with email and password.

    Raises:
        AuthError: If email is invalid (code: invalid_email, status: 400).
        AuthError: If email is already registered (code: user_exists, status: 409).
    """
    email = _validate_email(email)
    existing = await user_repo.get_user_by_email(session, email)
    if existing is not None:
        raise AuthError("Email already registered", code="user_exists", status_code=409)

    hashed = hash_password(password)
    user = await user_repo.create_user(
        session, email=email, password_hash=hashed, name=name,
    )

    await account_repo.create_account(
        session, user_id=user.id, provider="email", provider_account_id=email,
    )

    if events is not None:
        from authfort.events import Login, UserCreated

        events.collect("user_created", UserCreated(
            user_id=user.id, email=user.email, name=user.name, provider="email",
        ))
        events.collect("login", Login(
            user_id=user.id, email=user.email, provider="email",
            ip_address=ip_address, user_agent=user_agent,
        ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )


async def login(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    password: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Authenticate with email and password.

    Raises:
        AuthError: If credentials are invalid (code: invalid_credentials, status: 401).
    """
    email = email.strip().lower()
    user = await user_repo.get_user_by_email(session, email)
    if user is None:
        raise AuthError("Invalid email or password", code="invalid_credentials", status_code=401)

    if user.banned:
        raise AuthError("This account has been banned", code="user_banned", status_code=403)

    if user.password_hash is None:
        # OAuth-only account — tell the frontend so it can guide the user
        providers = [
            a.provider
            for a in await account_repo.get_accounts_by_user(session, user.id)
            if a.provider != "email"
        ]
        raise AuthError(
            "This account uses social login",
            code="oauth_account",
            status_code=401,
            providers=providers,
        )

    if not verify_password(password, user.password_hash):
        raise AuthError("Invalid email or password", code="invalid_credentials", status_code=401)

    if events is not None:
        from authfort.events import Login as LoginEvent

        events.collect("login", LoginEvent(
            user_id=user.id, email=user.email, provider="email",
            ip_address=ip_address, user_agent=user_agent,
        ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )


async def refresh(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    raw_refresh_token: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Refresh an access token using a refresh token.

    Implements refresh token rotation with theft detection:
    - Each refresh token is single-use
    - Reuse of a revoked token triggers nuclear revocation (all user sessions)

    Raises:
        AuthError: If refresh token is invalid, expired, or revoked.
    """
    token_hash = hash_refresh_token(raw_refresh_token)
    stored_token = await refresh_token_repo.get_refresh_token_by_hash(session, token_hash)

    if stored_token is None:
        raise AuthError("Invalid refresh token", code="refresh_token_invalid", status_code=401)

    if stored_token.revoked:
        await refresh_token_repo.revoke_all_user_refresh_tokens(session, stored_token.user_id)
        raise AuthError(
            "Refresh token reuse detected — all sessions revoked",
            code="refresh_token_revoked",
            status_code=401,
        )

    if stored_token.expires_at < datetime.now(UTC):
        raise AuthError("Refresh token expired", code="refresh_token_expired", status_code=401)

    user = await user_repo.get_user_by_id(session, stored_token.user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=401)

    if user.banned:
        raise AuthError("This account has been banned", code="user_banned", status_code=403)

    response = await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )

    new_token_hash = hash_refresh_token(response.tokens.refresh_token)
    new_stored = await refresh_token_repo.get_refresh_token_by_hash(session, new_token_hash)
    await refresh_token_repo.revoke_refresh_token(
        session, stored_token, replaced_by=new_stored.id if new_stored else None,
    )

    if events is not None:
        from authfort.events import TokenRefreshed

        events.collect("token_refreshed", TokenRefreshed(
            user_id=user.id, ip_address=ip_address, user_agent=user_agent,
        ))

    return response


async def logout(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    raw_refresh_token: str,
    events: EventCollector | None = None,
) -> None:
    """Logout — revoke the refresh token.

    Silently succeeds even if the token is invalid (don't leak info).
    """
    token_hash = hash_refresh_token(raw_refresh_token)
    stored_token = await refresh_token_repo.get_refresh_token_by_hash(session, token_hash)
    if stored_token is not None and not stored_token.revoked:
        await refresh_token_repo.revoke_refresh_token(session, stored_token)
        if events is not None:
            from authfort.events import Logout as LogoutEvent

            events.collect("logout", LogoutEvent(user_id=stored_token.user_id))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_or_create_signing_key(session: AsyncSession, config: AuthFortConfig):
    """Get the current signing key, or create one if none exists (first startup)."""
    key = await signing_key_repo.get_current_signing_key(session)
    if key is None:
        private_pem, public_pem = generate_key_pair()
        kid = generate_kid()
        key = await signing_key_repo.create_signing_key(
            session,
            kid=kid,
            private_key=private_pem,
            public_key=public_pem,
            algorithm=config.jwt_algorithm,
            is_current=True,
        )
    return key


async def _issue_tokens(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> AuthResponse:
    """Internal helper: create access token + refresh token for a user."""
    signing_key = await _get_or_create_signing_key(session, config)

    roles = await role_repo.get_roles(session, user.id)

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        roles=roles,
        token_version=user.token_version,
        kid=signing_key.kid,
        private_key=signing_key.private_key,
        config=config,
        name=user.name,
    )

    raw_refresh, refresh_hash = generate_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.refresh_token_expire_seconds)
    await refresh_token_repo.create_refresh_token(
        session,
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    user_response = UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        email_verified=user.email_verified,
        avatar_url=user.avatar_url,
        roles=roles,
        created_at=user.created_at,
    )

    tokens = AuthTokens(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=config.access_token_expire_seconds,
    )

    return AuthResponse(user=user_response, tokens=tokens)
