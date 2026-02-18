"""Core OAuth logic — state token management, PKCE, and user find-or-create.

Framework-agnostic. Called by integration adapters (FastAPI router, etc.).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import AuthError, _get_or_create_signing_key, _issue_tokens
from authfort.core.schemas import AuthResponse
from authfort.core.tokens import get_unverified_header
from authfort.providers.base import OAuthProvider, OAuthUserInfo
from authfort.repositories import account as account_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authfort.events import EventCollector

_STATE_TTL_SECONDS = 300  # 5 minutes


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256).

    Returns:
        (code_verifier, code_challenge) tuple.
    """
    code_verifier = secrets.token_urlsafe(64)  # 86 chars, well within 43-128 spec range
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


@dataclass(frozen=True, slots=True)
class OAuthState:
    """Result of creating OAuth state — contains the signed state token and PKCE values."""

    state: str
    code_verifier: str
    code_challenge: str


async def create_oauth_state(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    provider_name: str,
) -> OAuthState:
    """Create a signed JWT state token with PKCE code_verifier embedded.

    The state JWT contains the code_verifier so it can be recovered on callback
    without any server-side storage. The JWT is signed, so it can't be tampered with.

    Returns:
        OAuthState with state token, code_verifier, and code_challenge.
    """
    signing_key = await _get_or_create_signing_key(session, config)
    now = datetime.now(UTC)

    code_verifier, code_challenge = _generate_pkce()

    payload = {
        "typ": "oauth_state",
        "prv": provider_name,
        "nonce": secrets.token_urlsafe(16),
        "pkce": code_verifier,
        "iat": now,
        "exp": now + timedelta(seconds=_STATE_TTL_SECONDS),
        "iss": config.jwt_issuer,
    }

    state = jwt.encode(
        payload,
        signing_key.private_key,
        algorithm=config.jwt_algorithm,
        headers={"kid": signing_key.kid},
    )

    return OAuthState(state=state, code_verifier=code_verifier, code_challenge=code_challenge)


async def verify_oauth_state(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    state: str,
    expected_provider: str,
) -> str:
    """Verify the OAuth state token and extract the PKCE code_verifier.

    Returns:
        The code_verifier embedded in the state token.

    Raises:
        AuthError: If invalid, expired, or provider mismatch.
    """
    try:
        header = get_unverified_header(state)
    except jwt.InvalidTokenError:
        raise AuthError("Invalid OAuth state", code="oauth_state_invalid", status_code=400)

    kid = header.get("kid")
    if not kid:
        raise AuthError("Invalid OAuth state", code="oauth_state_invalid", status_code=400)

    signing_key = await signing_key_repo.get_signing_key_by_kid(session, kid)
    if signing_key is None:
        raise AuthError("Invalid OAuth state", code="oauth_state_invalid", status_code=400)

    try:
        payload = jwt.decode(
            state,
            signing_key.public_key,
            algorithms=[config.jwt_algorithm],
            issuer=config.jwt_issuer,
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("OAuth state expired", code="oauth_state_expired", status_code=400)
    except jwt.InvalidTokenError:
        raise AuthError("Invalid OAuth state", code="oauth_state_invalid", status_code=400)

    if payload.get("typ") != "oauth_state":
        raise AuthError("Invalid OAuth state", code="oauth_state_invalid", status_code=400)

    if payload.get("prv") != expected_provider:
        raise AuthError(
            "OAuth state provider mismatch",
            code="oauth_state_provider_mismatch",
            status_code=400,
        )

    return payload.get("pkce", "")


async def oauth_authenticate(
    session: AsyncSession,
    *,
    config: AuthFortConfig,
    provider: OAuthProvider,
    code: str,
    redirect_uri: str,
    code_verifier: str | None = None,
    user_agent: str | None = None,
    ip_address: str | None = None,
    events: "EventCollector | None" = None,
) -> AuthResponse:
    """Complete the OAuth flow: exchange code, fetch user info, find/create user, issue tokens.

    Auto-linking: if a user with the same email already exists, the OAuth
    account is linked to them automatically.
    """
    # Exchange code for provider tokens (with PKCE code_verifier)
    try:
        token_data = await provider.exchange_code(
            code=code, redirect_uri=redirect_uri, code_verifier=code_verifier,
        )
    except AuthError:
        raise
    except Exception as e:
        raise AuthError(
            f"Failed to exchange OAuth code: {e}",
            code="oauth_exchange_failed",
            status_code=400,
        )

    provider_access_token = token_data.get("access_token")
    if not provider_access_token:
        raise AuthError(
            "No access token in provider response",
            code="oauth_exchange_failed",
            status_code=400,
        )

    # Fetch user info from provider
    try:
        user_info: OAuthUserInfo = await provider.get_user_info(
            access_token=provider_access_token,
        )
    except AuthError:
        raise
    except Exception as e:
        raise AuthError(
            f"Failed to fetch user info from {provider.name}: {e}",
            code="oauth_user_info_failed",
            status_code=400,
        )

    # Find or create user
    account = await account_repo.get_account_by_provider(
        session, provider.name, user_info.provider_account_id,
    )

    if account is not None:
        # Returning user — load and update provider tokens
        user = await user_repo.get_user_by_id(session, account.user_id)
        if user is None:
            raise AuthError("User not found", code="user_not_found", status_code=401)

        account.access_token = user_info.access_token
        account.refresh_token = user_info.refresh_token
        session.add(account)
        await session.flush()
    else:
        # New OAuth link — auto-link by email or create new user
        user = await user_repo.get_user_by_email(session, user_info.email)
        is_new_user = user is None

        if is_new_user:
            user = await user_repo.create_user(
                session,
                email=user_info.email,
                password_hash=None,
                name=user_info.name,
                email_verified=user_info.email_verified,
            )
        elif user_info.email_verified and not user.email_verified:
            await user_repo.update_user(session, user, email_verified=True)

        await account_repo.create_account(
            session,
            user_id=user.id,
            provider=provider.name,
            provider_account_id=user_info.provider_account_id,
            access_token=user_info.access_token,
            refresh_token=user_info.refresh_token,
        )

        if events is not None:
            from authfort.events import OAuthLink, UserCreated

            if is_new_user:
                events.collect("user_created", UserCreated(
                    user_id=user.id, email=user.email, name=user.name,
                    provider=provider.name,
                ))
            else:
                events.collect("oauth_link", OAuthLink(
                    user_id=user.id, email=user.email, provider=provider.name,
                ))

    # Update profile fields if missing
    updates = {}
    if user.name is None and user_info.name is not None:
        updates["name"] = user_info.name
    if user.avatar_url is None and user_info.avatar_url is not None:
        updates["avatar_url"] = user_info.avatar_url
    if updates:
        user = await user_repo.update_user(session, user, **updates)

    if events is not None:
        from authfort.events import Login

        events.collect("login", Login(
            user_id=user.id, email=user.email, provider=provider.name,
            ip_address=ip_address, user_agent=user_agent,
        ))

    return await _issue_tokens(
        session, config=config, user=user, user_agent=user_agent, ip_address=ip_address,
    )
