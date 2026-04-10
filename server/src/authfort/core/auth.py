"""Core auth service — signup, login, refresh, logout.

Framework-agnostic business logic. All functions take an AsyncSession and config.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import JWT_ALGORITHM, AuthFortConfig
from authfort.core.keys import generate_key_pair, generate_kid
from authfort.core.refresh import generate_otp, generate_refresh_token, hash_refresh_token
from authfort.core.schemas import AuthResponse, AuthTokens, MFAChallenge, MFASetup, MFAStatus, UserResponse
from authfort.core.tokens import create_access_token
from authfort.repositories import account as account_repo
from authfort.repositories import mfa_backup_code as backup_code_repo
from authfort.repositories import refresh_token as refresh_token_repo
from authfort.repositories import role as role_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo
from authfort.repositories import user_mfa as user_mfa_repo
from authfort.repositories import verification_token as verification_token_repo
from authfort.core.errors import AuthError
from authfort.core.validation import (
    sanitize_name,
    sanitize_phone,
    validate_avatar_url,
    validate_password,
    validate_user_email,
)
from authfort.utils.passwords import hash_password, verify_password

if TYPE_CHECKING:
    from authfort.events import EventCollector


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
    email_verified: bool = False,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Register a new user with email and password.

    Raises:
        AuthError: If email is invalid (code: invalid_email, status: 400).
        AuthError: If email is already registered (code: user_exists, status: 409).
    """
    email = validate_user_email(email)
    validate_password(password, min_length=config.min_password_length)
    name = sanitize_name(name)
    phone = sanitize_phone(phone)
    avatar_url = validate_avatar_url(avatar_url)

    existing = await user_repo.get_user_by_email(session, email)
    if existing is not None:
        raise AuthError("Email already registered", code="user_exists", status_code=409)

    hashed = hash_password(password)
    user = await user_repo.create_user(
        session, email=email, password_hash=hashed, name=name,
        avatar_url=avatar_url, phone=phone,
        email_verified=email_verified,
    )

    await account_repo.create_account(
        session, user_id=user.id, provider="email", provider_account_id=email,
    )

    if events is not None:
        from authfort.events import EmailVerified, Login, UserCreated

        events.collect("user_created", UserCreated(
            user_id=user.id, email=user.email, name=user.name, provider="email",
        ))
        events.collect("login", Login(
            user_id=user.id, email=user.email, provider="email",
            ip_address=ip_address, user_agent=user_agent,
        ))
        if email_verified:
            events.collect("email_verified", EmailVerified(
                user_id=user.id, email=user.email,
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
) -> AuthResponse | MFAChallenge:
    """Authenticate with email and password.

    If the user has TOTP MFA enabled, returns ``MFAChallenge`` instead of tokens.
    The client must POST the ``mfa_token`` + TOTP code to ``/auth/mfa/verify``
    to complete the login.

    Raises:
        AuthError: If credentials are invalid (code: invalid_credentials, status: 401).
    """
    email = validate_user_email(email)
    user = await user_repo.get_user_by_email(session, email)
    if user is None:
        raise AuthError("Invalid email or password", code="invalid_credentials", status_code=401)

    if user.password_hash is None:
        # No password set — distinguish OAuth from passwordless
        providers = [
            a.provider
            for a in await account_repo.get_accounts_by_user(session, user.id)
            if a.provider != "email"
        ]
        if providers:
            raise AuthError(
                "This account uses social login",
                code="oauth_account",
                status_code=400,
                providers=providers,
            )
        raise AuthError(
            "This account uses passwordless login. You can set a password via forgot-password or set-password.",
            code="no_password",
            status_code=400,
        )

    if not verify_password(password, user.password_hash):
        raise AuthError("Invalid email or password", code="invalid_credentials", status_code=401)

    if user.banned:
        raise AuthError("This account has been banned", code="user_banned", status_code=403)

    # Check MFA — if enabled, return a challenge instead of tokens
    user_mfa = await user_mfa_repo.get_user_mfa(session, user.id)
    if user_mfa is not None and user_mfa.enabled:
        signing_key = await _get_or_create_signing_key(session, config)
        from authfort.core.mfa import create_mfa_challenge_token, MFA_CHALLENGE_TTL_SECONDS

        mfa_token = create_mfa_challenge_token(
            user.id, signing_key.private_key, signing_key.kid, config,
        )
        return MFAChallenge(mfa_token=mfa_token, expires_in=MFA_CHALLENGE_TTL_SECONDS)

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
        session_id=stored_token.session_id or stored_token.id,
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

    Returns the raw token string if the user exists,
    or None if the user is not found (prevents user enumeration).
    Works for all users — password, OAuth, and passwordless.
    Passwordless users can use this to set their initial password.

    The caller is responsible for delivering the token (email, SMS, etc.).
    """
    email = validate_user_email(email)
    user = await user_repo.get_user_by_email(session, email)
    if user is None:
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
    validate_password(new_password, min_length=config.min_password_length)

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
    had_password = user.password_hash is not None
    await user_repo.update_user(session, user, password_hash=hashed)
    await user_repo.bump_token_version(session, user.id)
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user.id)
    await verification_token_repo.delete_verification_token(session, stored.id)

    # If user had no password (passwordless/OAuth), create an email account record
    if not had_password:
        existing_email_account = await account_repo.get_user_account_by_provider(
            session, user.id, "email",
        )
        if existing_email_account is None:
            await account_repo.create_account(
                session, user_id=user.id, provider="email",
                provider_account_id=user.email,
            )

    if events is not None:
        from authfort.events import PasswordReset as PasswordResetEvent

        events.collect("password_reset", PasswordResetEvent(user_id=user.id))

    return True


async def change_password(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
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
        AuthError: If new password is too short (code: password_too_short, status: 400).
    """
    validate_password(new_password, min_length=config.min_password_length)
    user = await user_repo.get_user_by_id(session, user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=404)

    if user.password_hash is None:
        # No password set — distinguish OAuth from passwordless
        providers = [
            a.provider
            for a in await account_repo.get_accounts_by_user(session, user.id)
            if a.provider != "email"
        ]
        if providers:
            raise AuthError(
                "This account uses social login",
                code="oauth_account",
                status_code=400,
                providers=providers,
            )
        raise AuthError(
            "This account uses passwordless login. Use set-password to add a password.",
            code="no_password",
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


async def set_password(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
    new_password: str,
    events: EventCollector | None = None,
) -> None:
    """Set an initial password for a passwordless user (magic link, OTP, OAuth).

    Only works when the user has no password set. If they already have one,
    use change_password instead.

    Raises:
        AuthError: If user not found (code: user_not_found, status: 404).
        AuthError: If user already has a password (code: password_already_set, status: 400).
        AuthError: If new password is too short (code: password_too_short, status: 400).
    """
    validate_password(new_password, min_length=config.min_password_length)
    user = await user_repo.get_user_by_id(session, user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=404)

    if user.password_hash is not None:
        raise AuthError(
            "Password already set. Use change-password instead.",
            code="password_already_set",
            status_code=400,
        )

    hashed = hash_password(new_password)
    await user_repo.update_user(session, user, password_hash=hashed)
    await user_repo.bump_token_version(session, user.id)
    await refresh_token_repo.revoke_all_user_refresh_tokens(session, user.id)

    # Create email account record if missing
    existing_email_account = await account_repo.get_user_account_by_provider(
        session, user.id, "email",
    )
    if existing_email_account is None:
        await account_repo.create_account(
            session, user_id=user.id, provider="email",
            provider_account_id=user.email,
        )

    if events is not None:
        from authfort.events import PasswordSet

        events.collect("password_set", PasswordSet(user_id=user.id))


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
    email = validate_user_email(email)
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
    email = validate_user_email(email)
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
    email = validate_user_email(email)
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
# MFA — setup, verify, disable
# ---------------------------------------------------------------------------

async def complete_mfa_login(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    mfa_token: str,
    code: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: EventCollector | None = None,
) -> AuthResponse:
    """Complete a login that requires MFA by verifying the TOTP or backup code.

    Args:
        mfa_token: The short-lived challenge token returned by login().
        code: 6-digit TOTP code or backup code submitted by the user.

    Raises:
        AuthError: If the challenge token is invalid/expired (code: invalid_mfa_token).
        AuthError: If the TOTP/backup code is wrong (code: invalid_mfa_code).
        AuthError: If the user is banned (code: user_banned).
    """
    from authfort.core.mfa import verify_mfa_challenge_token, verify_totp_code, verify_backup_code
    import jwt as pyjwt

    # Resolve the public key for the token's kid
    signing_key = await _get_or_create_signing_key(session, config)
    try:
        user_id = verify_mfa_challenge_token(mfa_token, signing_key.public_key, config)
    except pyjwt.ExpiredSignatureError:
        raise AuthError("MFA session expired, please log in again", code="invalid_mfa_token", status_code=401)
    except pyjwt.InvalidTokenError:
        raise AuthError("Invalid MFA token", code="invalid_mfa_token", status_code=401)

    user = await user_repo.get_user_by_id(session, user_id)
    if user is None or user.banned:
        raise AuthError("Invalid MFA token", code="invalid_mfa_token", status_code=401)

    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None or not user_mfa.enabled:
        raise AuthError("MFA not enabled for this user", code="invalid_mfa_token", status_code=401)

    # Try TOTP code first, then backup codes
    used_backup = False
    if len(code) == 6 and code.isdigit():
        if not verify_totp_code(
            user_mfa.totp_secret, code,
            last_used_at=user_mfa.last_used_at,
            last_used_code=user_mfa.last_used_code,
        ):
            if events is not None:
                from authfort.events import MFAFailed
                events.collect("mfa_failed", MFAFailed(
                    user_id=user.id, email=user.email, ip_address=ip_address,
                ))
            raise AuthError("Invalid or expired MFA code", code="invalid_mfa_code", status_code=401)
        # Update replay protection state
        from authfort.utils import utc_now
        await user_mfa_repo.update_last_used(session, user_mfa, code=code, used_at=utc_now())
    else:
        # Backup code path
        unused_codes = await backup_code_repo.get_unused_backup_codes(session, user_id)
        code_hashes = [bc.code_hash for bc in unused_codes]
        matched_hash = verify_backup_code(code, code_hashes)
        if matched_hash is None:
            if events is not None:
                from authfort.events import MFAFailed
                events.collect("mfa_failed", MFAFailed(
                    user_id=user.id, email=user.email, ip_address=ip_address,
                ))
            raise AuthError("Invalid MFA code", code="invalid_mfa_code", status_code=401)
        matched_code = next(bc for bc in unused_codes if bc.code_hash == matched_hash)
        await backup_code_repo.mark_backup_code_used(session, matched_code)
        used_backup = True

    if events is not None:
        from authfort.events import Login as LoginEvent, MFALogin, BackupCodeUsed

        events.collect("login", LoginEvent(
            user_id=user.id, email=user.email, provider="email",
            ip_address=ip_address, user_agent=user_agent,
        ))
        events.collect("mfa_login", MFALogin(
            user_id=user.id, email=user.email, ip_address=ip_address,
        ))
        if used_backup:
            events.collect("backup_code_used", BackupCodeUsed(
                user_id=user.id, email=user.email,
            ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )


async def enable_mfa_init(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
) -> MFASetup:
    """Start TOTP MFA setup — generate a secret and return the QR URI.

    Does NOT enable MFA yet. The user must call enable_mfa_confirm() with
    a valid TOTP code to activate it.

    If setup was previously initiated but not confirmed, the old secret is
    replaced so the user starts fresh.

    Raises:
        AuthError: If user not found (code: user_not_found).
        AuthError: If MFA is already enabled (code: mfa_already_enabled).
    """
    from authfort.core.mfa import generate_totp_secret, get_totp_uri

    user = await user_repo.get_user_by_id(session, user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=404)

    existing = await user_mfa_repo.get_user_mfa(session, user_id)
    if existing is not None and existing.enabled:
        raise AuthError("MFA is already enabled", code="mfa_already_enabled", status_code=400)

    secret = generate_totp_secret()
    issuer = config.mfa_issuer or config.jwt_issuer
    qr_uri = get_totp_uri(secret, user.email, issuer)

    if existing is not None:
        # Replace stale unconfirmed setup
        existing.totp_secret = secret
        await session.flush()
    else:
        await user_mfa_repo.create_user_mfa(session, user_id=user_id, totp_secret=secret)

    return MFASetup(secret=secret, qr_uri=qr_uri)


async def enable_mfa_confirm(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
    code: str,
    events: EventCollector | None = None,
) -> list[str]:
    """Confirm TOTP setup by verifying the first code, then enable MFA.

    Returns the plaintext backup codes — shown exactly once. The caller
    must display them to the user immediately.

    Raises:
        AuthError: If MFA setup was not initiated (code: mfa_not_initiated).
        AuthError: If MFA is already enabled (code: mfa_already_enabled).
        AuthError: If the TOTP code is wrong (code: invalid_mfa_code).
    """
    from authfort.core.mfa import verify_totp_code, generate_backup_codes, hash_backup_code

    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None:
        raise AuthError("MFA setup not initiated. Call enable_mfa_init first.", code="mfa_not_initiated", status_code=400)
    if user_mfa.enabled:
        raise AuthError("MFA is already enabled", code="mfa_already_enabled", status_code=400)

    if not verify_totp_code(
        user_mfa.totp_secret, code,
        last_used_at=None,
        last_used_code=None,
    ):
        raise AuthError("Invalid TOTP code", code="invalid_mfa_code", status_code=400)

    await user_mfa_repo.enable_user_mfa(session, user_mfa, code=code)

    # Generate and store backup codes
    plaintext_codes = generate_backup_codes(config.mfa_backup_code_count)
    code_hashes = [hash_backup_code(c) for c in plaintext_codes]
    await backup_code_repo.create_backup_codes(session, user_id=user_id, code_hashes=code_hashes)

    if events is not None:
        user = await user_repo.get_user_by_id(session, user_id)
        if user is not None:
            from authfort.events import MFAEnabled
            events.collect("mfa_enabled", MFAEnabled(user_id=user_id, email=user.email))

    return plaintext_codes


async def disable_mfa(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
    code: str,
    events: EventCollector | None = None,
) -> None:
    """Disable TOTP MFA for a user. Requires a valid TOTP code or backup code.

    Deletes the MFA record and all backup codes.

    Raises:
        AuthError: If MFA is not enabled (code: mfa_not_enabled).
        AuthError: If the code is invalid (code: invalid_mfa_code).
    """
    from authfort.core.mfa import verify_totp_code, verify_backup_code

    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None or not user_mfa.enabled:
        raise AuthError("MFA is not enabled", code="mfa_not_enabled", status_code=400)

    verified = False
    if len(code) == 6 and code.isdigit():
        verified = verify_totp_code(
            user_mfa.totp_secret, code,
            last_used_at=user_mfa.last_used_at,
            last_used_code=user_mfa.last_used_code,
        )
    else:
        unused_codes = await backup_code_repo.get_unused_backup_codes(session, user_id)
        verified = verify_backup_code(code, [bc.code_hash for bc in unused_codes]) is not None

    if not verified:
        raise AuthError("Invalid MFA code", code="invalid_mfa_code", status_code=400)

    await backup_code_repo.delete_backup_codes_for_user(session, user_id)
    await user_mfa_repo.disable_user_mfa(session, user_mfa)

    if events is not None:
        user = await user_repo.get_user_by_id(session, user_id)
        if user is not None:
            from authfort.events import MFADisabled
            events.collect("mfa_disabled", MFADisabled(user_id=user_id, email=user.email))


async def admin_disable_mfa(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    events: EventCollector | None = None,
) -> None:
    """Disable MFA for a user without requiring a code (admin/support override).

    Use for account recovery when the user has lost their authenticator and
    backup codes, after verifying their identity out-of-band.

    Raises:
        AuthError: If MFA is not enabled (code: mfa_not_enabled).
    """
    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None or not user_mfa.enabled:
        raise AuthError("MFA is not enabled", code="mfa_not_enabled", status_code=400)

    await backup_code_repo.delete_backup_codes_for_user(session, user_id)
    await user_mfa_repo.disable_user_mfa(session, user_mfa)

    if events is not None:
        user = await user_repo.get_user_by_id(session, user_id)
        if user is not None:
            from authfort.events import MFADisabled
            events.collect("mfa_disabled", MFADisabled(user_id=user_id, email=user.email))


async def regenerate_backup_codes(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    user_id: uuid.UUID,
    totp_code: str,
    events: EventCollector | None = None,
) -> list[str]:
    """Regenerate backup codes. Requires a valid TOTP code. Old codes are deleted.

    Returns new plaintext backup codes — shown exactly once.

    Raises:
        AuthError: If MFA is not enabled (code: mfa_not_enabled).
        AuthError: If the TOTP code is invalid (code: invalid_mfa_code).
    """
    from authfort.core.mfa import verify_totp_code, generate_backup_codes, hash_backup_code

    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None or not user_mfa.enabled:
        raise AuthError("MFA is not enabled", code="mfa_not_enabled", status_code=400)

    if not verify_totp_code(
        user_mfa.totp_secret, totp_code,
        last_used_at=user_mfa.last_used_at,
        last_used_code=user_mfa.last_used_code,
    ):
        raise AuthError("Invalid TOTP code", code="invalid_mfa_code", status_code=400)

    await backup_code_repo.delete_backup_codes_for_user(session, user_id)
    plaintext_codes = generate_backup_codes(config.mfa_backup_code_count)
    code_hashes = [hash_backup_code(c) for c in plaintext_codes]
    await backup_code_repo.create_backup_codes(session, user_id=user_id, code_hashes=code_hashes)

    if events is not None:
        user = await user_repo.get_user_by_id(session, user_id)
        if user is not None:
            from authfort.events import BackupCodesRegenerated
            events.collect("backup_codes_regenerated", BackupCodesRegenerated(
                user_id=user_id, email=user.email,
            ))

    return plaintext_codes


async def get_mfa_status(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
) -> MFAStatus:
    """Return current MFA status for a user.

    Raises:
        AuthError: If user not found (code: user_not_found).
    """
    user = await user_repo.get_user_by_id(session, user_id)
    if user is None:
        raise AuthError("User not found", code="user_not_found", status_code=404)

    user_mfa = await user_mfa_repo.get_user_mfa(session, user_id)
    if user_mfa is None or not user_mfa.enabled:
        return MFAStatus(enabled=False, backup_codes_remaining=0)

    remaining = await backup_code_repo.count_remaining(session, user_id)
    return MFAStatus(enabled=True, backup_codes_remaining=remaining)


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
    session_id: uuid.UUID | None = None,
) -> AuthResponse:
    """Internal helper: create access token + refresh token for a user.

    Args:
        session_id: Stable session identifier. If None (new login/signup),
            the token's own id is used. If provided (refresh), carried forward.
    """
    signing_key = await _get_or_create_signing_key(session, config)

    roles = await role_repo.get_roles(session, user.id)

    # Check MFA status to embed in the JWT claim
    user_mfa = await user_mfa_repo.get_user_mfa(session, user.id)
    mfa_enabled = user_mfa is not None and user_mfa.enabled

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
        session_id=session_id,
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
        session_id=stored_token.session_id,
        mfa_enabled=mfa_enabled,
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
        session_id=stored_token.session_id,
        mfa_enabled=mfa_enabled,
    )

    tokens = AuthTokens(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=config.access_token_expire_seconds,
    )

    return AuthResponse(user=user_response, tokens=tokens)
