"""Smoke tests — verify all modules import cleanly."""


def test_import_models():
    from authfort.models import (
        Account,
        RefreshToken,
        SigningKey,
        User,
        UserRole,
        VerificationToken,
    )


def test_import_core():
    from authfort.core.auth import AuthError, login, logout, refresh, signup
    from authfort.core.keys import generate_key_pair, generate_kid, public_key_to_jwk
    from authfort.core.refresh import generate_refresh_token, hash_refresh_token
    from authfort.core.schemas import (
        AuthResponse,
        AuthTokens,
        LoginRequest,
        RefreshRequest,
        SignupRequest,
        UserResponse,
    )
    from authfort.core.tokens import (
        create_access_token,
        get_unverified_header,
        verify_access_token,
    )


def test_import_repositories():
    from authfort.repositories import account
    from authfort.repositories import refresh_token
    from authfort.repositories import role
    from authfort.repositories import signing_key
    from authfort.repositories import user
    from authfort.repositories import verification_token


def test_import_utils():
    from authfort.utils.passwords import hash_password, verify_password


def test_import_config():
    from authfort.config import AuthFortConfig, CookieConfig


def test_import_authfort():
    from authfort import AuthFort, CookieConfig


def test_import_db():
    from authfort.db import create_engine, create_session_factory, get_session


def test_import_fastapi_integration():
    from authfort.integrations.fastapi import (
        create_auth_router,
        create_current_user_dep,
        create_oauth_router,
        create_require_role_dep,
    )


def test_import_providers():
    from authfort.providers import GitHubProvider, GoogleProvider, OAuthProvider, OAuthUserInfo


def test_import_providers_from_top_level():
    from authfort import GitHubProvider, GoogleProvider


def test_import_oauth_core():
    from authfort.core.oauth import create_oauth_state, oauth_authenticate, verify_oauth_state


def test_import_sessions():
    from authfort.core.sessions import get_sessions, revoke_all_sessions, revoke_session
    from authfort.core.schemas import SessionResponse


def test_import_session_response_from_top_level():
    from authfort import SessionResponse


def test_import_events():
    from authfort.events import (
        Event,
        EventCollector,
        HookRegistry,
        KeyRotated,
        Login,
        LoginFailed,
        Logout,
        OAuthLink,
        RoleAdded,
        RoleRemoved,
        SessionRevoked,
        TokenRefreshed,
        UserBanned,
        UserCreated,
        UserUnbanned,
        get_collector,
    )


def test_import_jwks_router():
    from authfort.integrations.fastapi.jwks_router import create_jwks_router


def test_import_introspect_router():
    from authfort.integrations.fastapi.introspect_router import create_introspect_router


def test_import_auth_error_from_top_level():
    from authfort import AuthError
