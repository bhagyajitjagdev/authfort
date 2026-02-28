"""Core auth service — signup, login, refresh, logout.

Framework-agnostic business logic. All functions take an AsyncSession and config.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import JWT_ALGORITHM, AuthFortConfig
from authfort.core.keys import generate_key_pair, generate_kid
from authfort.core.refresh import generate_otp, generate_refresh_token, hash_refresh_token
from authfort.core.schemas import AuthResponse, AuthTokens, UserResponse
from authfort.core.tokens import create_access_token
from authfort.repositories import account as account_repo
from authfort.repositories import refresh_token as refresh_token_repo
from authfort.repositories import role as role_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo
from authfort.repositories import verification_token as verification_token_repo
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
    avatar_url: str | None = None,
    phone: str | None = None,
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
        avatar_url=avatar_url, phone=phone,
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
            status_code=400,
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


async def create_password_reset_token(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    events: EventCollector | None = None,
) -> str | None:
    """Create a password reset token for a user.

    Returns the raw token string if the user exists and has a password,
    or None if the user is not found or is OAuth-only (prevents user enumeration).

    The caller is responsible for delivering the token (email, SMS, etc.).
    """
    email = email.strip().lower()
    user = await user_repo.get_user_by_email(session, email)
    if user is None or user.password_hash is None:
        return None

    # Delete any existing password_reset tokens for this user
    await verification_token_repo.delete_verification_tokens_by_user_and_type(
        session, user.id, "password_reset",
    )

    raw_token, token_hash = generate_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.password_reset_ttl_seconds)
    await verification_token_repo.create_verification_token(
        session,
        user_id=user.id,
        token_hash=token_hash,
        type="password_reset",
        expires_at=expires_at,
    )

    if events is not None:
        from authfort.events import PasswordResetRequested

        events.collect("password_reset_requested", PasswordResetRequested(
            user_id=user.id, email=user.email,
        ))

    return raw_token


async def reset_password(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    token: str,
    new_password: str,
    events: EventCollector | None = None,
) -> bool:
    """Reset a user's password using a reset token.

    Validates the token, updates the password, bumps token_version
    (invalidating all existing JWTs), and deletes the token.

    Raises:
        AuthError: If the token is invalid or expired (code: invalid_reset_token).
    """
    token_hash = hash_refresh_token(token)
    stored = await verification_token_repo.get_verification_token_by_hash(session, token_hash)

    if stored is None or stored.type != "password_reset":
        raise AuthError(
            "Invalid or expired reset token",
            code="invalid_reset_token",
            status_code=400,
        )

    if stored.expires_at < datetime.now(UTC):
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired reset token",
            code="invalid_reset_token",
            status_code=400,
        )

    user = await user_repo.get_user_by_id(session, stored.user_id)
    if user is None:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired reset token",
            code="invalid_reset_token",
            status_code=400,
        )

    hashed = hash_password(new_password)
    await user_repo.update_user(session, user, password_hash=hashed)
    await user_repo.bump_token_version(session, user.id)
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user.id)
    await verification_token_repo.delete_verification_token(session, stored.id)

    if events is not None:
        from authfort.events import PasswordReset as PasswordResetEvent

        events.collect("password_reset", PasswordResetEvent(user_id=user.id))

    return True


async def change_password(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    old_password: str,
    new_password: str,
    events: EventCollector | None = None,
) -> None:
    """Change a user's password (requires the old password).

    Verifies the old password, hashes the new one, bumps token_version
    to invalidate all existing JWTs (forces re-login everywhere).

    Raises:
        AuthError: If user not found (code: user_not_found, status: 404).
        AuthError: If user is OAuth-only (code: oauth_account, status: 400).
        AuthError: If old password is wrong (code: invalid_password, status: 400).
    """
    user = await user_repo.get_user_by_id(session, user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=404)

    if user.password_hash is None:
        raise AuthError(
            "This account uses social login",
            code="oauth_account",
            status_code=400,
        )

    if not verify_password(old_password, user.password_hash):
        raise AuthError("Invalid password", code="invalid_password", status_code=400)

    hashed = hash_password(new_password)
    await user_repo.update_user(session, user, password_hash=hashed)
    await user_repo.bump_token_version(session, user.id)
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user.id)

    if events is not None:
        from authfort.events import PasswordChanged

        events.collect("password_changed", PasswordChanged(user_id=user.id))


async def create_email_verification_token(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
    events: EventCollector | None = None,
) -> str | None:
    """Create an email verification token for a user.

    Returns the raw token string if the user exists and is not yet verified,
    or None if the user is not found or already verified.

    The caller is responsible for delivering the token (email, etc.).
    """
    user = await user_repo.get_user_by_id(session, user_id)
    if user is None or user.email_verified:
        return None

    # Delete any existing email_verify tokens for this user
    await verification_token_repo.delete_verification_tokens_by_user_and_type(
        session, user.id, "email_verify",
    )

    raw_token, token_hash = generate_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.email_verify_ttl_seconds)
    await verification_token_repo.create_verification_token(
        session,
        user_id=user.id,
        token_hash=token_hash,
        type="email_verify",
        expires_at=expires_at,
    )

    if events is not None:
        from authfort.events import EmailVerificationRequested

        events.collect("email_verification_requested", EmailVerificationRequested(
            user_id=user.id, email=user.email, token=raw_token,
        ))

    return raw_token


async def verify_email(
    session: AsyncSession,
    *,
    token: str,
    events: EventCollector | None = None,
) -> bool:
    """Verify a user's email using a verification token.

    Validates the token, sets email_verified=True, and deletes the token.

    Raises:
        AuthError: If the token is invalid or expired (code: invalid_verification_token).
    """
    token_hash = hash_refresh_token(token)
    stored = await verification_token_repo.get_verification_token_by_hash(session, token_hash)

    if stored is None or stored.type != "email_verify":
        raise AuthError(
            "Invalid or expired verification token",
            code="invalid_verification_token",
            status_code=400,
        )

    if stored.expires_at < datetime.now(UTC):
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired verification token",
            code="invalid_verification_token",
            status_code=400,
        )

    user = await user_repo.get_user_by_id(session, stored.user_id)
    if user is None:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired verification token",
            code="invalid_verification_token",
            status_code=400,
        )

    await user_repo.update_user(session, user, email_verified=True)
    await verification_token_repo.delete_verification_token(session, stored.id)

    if events is not None:
        from authfort.events import EmailVerified

        events.collect("email_verified", EmailVerified(
            user_id=user.id, email=user.email,
        ))

    return True


async def create_magic_link_token(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    events: EventCollector | None = None,
) -> str | None:
    """Create a magic link token for passwordless login.

    Returns the raw token string if the user exists (or was created via
    passwordless signup), or None if the user is not found and signup
    is not allowed, or the user is banned.

    The caller is responsible for delivering the token (email, etc.).
    """
    email = email.strip().lower()
    user = await user_repo.get_user_by_email(session, email)

    if user is None and config.allow_passwordless_signup:
        user = await user_repo.create_user(session, email=email)
        if events is not None:
            from authfort.events import UserCreated

            events.collect("user_created", UserCreated(
                provider="magic_link", email=email, user_id=user.id,
            ))

    if user is None:
        return None

    if user.banned:
        return None

    # Delete any existing magic_link tokens for this user
    await verification_token_repo.delete_verification_tokens_by_user_and_type(
        session, user.id, "magic_link",
    )

    raw_token, token_hash = generate_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.magic_link_ttl_seconds)
    await verification_token_repo.create_verification_token(
        session,
        user_id=user.id,
        token_hash=token_hash,
        type="magic_link",
        expires_at=expires_at,
    )

    if events is not None:
        from authfort.events import MagicLinkRequested

        events.collect("magic_link_requested", MagicLinkRequested(
            user_id=user.id, email=user.email, token=raw_token,
        ))

    return raw_token


async def verify_magic_link(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    token: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Verify a magic link token and log the user in.

    Validates the token, marks email as verified, deletes the token,
    and issues access + refresh tokens.

    Raises:
        AuthError: If the token is invalid or expired (code: invalid_magic_link).
        AuthError: If the user is banned (code: user_banned, status: 403).
    """
    token_hash = hash_refresh_token(token)
    stored = await verification_token_repo.get_verification_token_by_hash(session, token_hash)

    if stored is None or stored.type != "magic_link":
        raise AuthError(
            "Invalid or expired magic link",
            code="invalid_magic_link",
            status_code=400,
        )

    if stored.expires_at < datetime.now(UTC):
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired magic link",
            code="invalid_magic_link",
            status_code=400,
        )

    user = await user_repo.get_user_by_id(session, stored.user_id)
    if user is None:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired magic link",
            code="invalid_magic_link",
            status_code=400,
        )

    if user.banned:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "This account has been banned",
            code="user_banned",
            status_code=403,
        )

    if not user.email_verified:
        await user_repo.update_user(session, user, email_verified=True)

    await verification_token_repo.delete_verification_token(session, stored.id)

    if events is not None:
        from authfort.events import MagicLinkLogin

        events.collect("magic_link_login", MagicLinkLogin(
            user_id=user.id, email=user.email,
        ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )


async def create_email_otp(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    events: EventCollector | None = None,
) -> str | None:
    """Create an email OTP code for passwordless login.

    Returns the raw OTP code if the user exists (or was created via
    passwordless signup), or None if the user is not found and signup
    is not allowed, or the user is banned.

    The caller is responsible for delivering the code (email, etc.).
    """
    email = email.strip().lower()
    user = await user_repo.get_user_by_email(session, email)

    if user is None and config.allow_passwordless_signup:
        user = await user_repo.create_user(session, email=email)
        if events is not None:
            from authfort.events import UserCreated

            events.collect("user_created", UserCreated(
                provider="email_otp", email=email, user_id=user.id,
            ))

    if user is None:
        return None

    if user.banned:
        return None

    # Delete any existing email_otp tokens for this user
    await verification_token_repo.delete_verification_tokens_by_user_and_type(
        session, user.id, "email_otp",
    )

    raw_code, code_hash = generate_otp()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.email_otp_ttl_seconds)
    await verification_token_repo.create_verification_token(
        session,
        user_id=user.id,
        token_hash=code_hash,
        type="email_otp",
        expires_at=expires_at,
    )

    if events is not None:
        from authfort.events import EmailOTPRequested

        events.collect("email_otp_requested", EmailOTPRequested(
            user_id=user.id, email=user.email, code=raw_code,
        ))

    return raw_code


async def verify_email_otp(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    email: str,
    code: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Verify an email OTP code and log the user in.

    Validates the code, marks email as verified, deletes the token,
    and issues access + refresh tokens.

    Raises:
        AuthError: If the code is invalid or expired (code: invalid_otp).
        AuthError: If the user is banned (code: user_banned, status: 403).
    """
    email = email.strip().lower()
    token_hash = hash_refresh_token(code)
    stored = await verification_token_repo.get_verification_token_by_hash(session, token_hash)

    if stored is None or stored.type != "email_otp":
        raise AuthError(
            "Invalid or expired OTP code",
            code="invalid_otp",
            status_code=400,
        )

    if stored.expires_at < datetime.now(UTC):
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired OTP code",
            code="invalid_otp",
            status_code=400,
        )

    user = await user_repo.get_user_by_id(session, stored.user_id)
    if user is None:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "Invalid or expired OTP code",
            code="invalid_otp",
            status_code=400,
        )

    if user.email != email:
        raise AuthError(
            "Invalid or expired OTP code",
            code="invalid_otp",
            status_code=400,
        )

    if user.banned:
        await verification_token_repo.delete_verification_token(session, stored.id)
        raise AuthError(
            "This account has been banned",
            code="user_banned",
            status_code=403,
        )

    if not user.email_verified:
        await user_repo.update_user(session, user, email_verified=True)

    await verification_token_repo.delete_verification_token(session, stored.id)

    if events is not None:
        from authfort.events import EmailOTPLogin

        events.collect("email_otp_login", EmailOTPLogin(
            user_id=user.id, email=user.email,
        ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_or_create_signing_key(session: AsyncSession, config: AuthFortConfig):
    """Get the current signing key, or create one if none exists (first startup)."""
    key = await signing_key_repo.get_current_signing_key(session)
    if key is None:
        private_pem, public_pem = generate_key_pair(config.rsa_key_size)
        kid = generate_kid()
        key = await signing_key_repo.create_signing_key(
            session,
            kid=kid,
            private_key=private_pem,
            public_key=public_pem,
            algorithm=JWT_ALGORITHM,
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

    # Create refresh token first so we can embed session_id in the JWT
    raw_refresh, refresh_hash = generate_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.refresh_token_expire_seconds)
    stored_token = await refresh_token_repo.create_refresh_token(
        session,
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        roles=roles,
        token_version=user.token_version,
        kid=signing_key.kid,
        private_key=signing_key.private_key,
        config=config,
        name=user.name,
        session_id=stored_token.id,
    )

    user_response = UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        email_verified=user.email_verified,
        avatar_url=user.avatar_url,
        phone=user.phone,
        banned=user.banned,
        roles=roles,
        created_at=user.created_at,
        session_id=stored_token.id,
    )

    tokens = AuthTokens(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=config.access_token_expire_seconds,
    )

    return AuthResponse(user=user_response, tokens=tokens)
