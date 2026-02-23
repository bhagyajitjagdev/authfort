"""AuthFort — Authentication and authorization library for Python."""

__version__ = "0.0.9"

from authfort.alembic_helper import alembic_exclude
from authfort.authfort import AuthFort
from authfort.config import CookieConfig
from authfort.core.auth import AuthError
from authfort.core.schemas import AuthResponse, AuthTokens, SessionResponse, UserResponse
from authfort.events import (
    EmailOTPLogin,
    EmailOTPRequested,
    EmailVerificationRequested,
    EmailVerified,
    KeyRotated,
    Login,
    LoginFailed,
    Logout,
    MagicLinkLogin,
    MagicLinkRequested,
    OAuthLink,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    RoleAdded,
    RoleRemoved,
    SessionRevoked,
    TokenRefreshed,
    UserBanned,
    UserCreated,
    UserUnbanned,
    UserUpdated,
)
from authfort.providers.generic import GenericOAuthProvider, GenericOIDCProvider
from authfort.providers.github import GitHubProvider
from authfort.providers.google import GoogleProvider

__all__ = [
    "AuthFort",
    "AuthError",
    "AuthResponse",
    "AuthTokens",
    "CookieConfig",
    "EmailOTPLogin",
    "EmailOTPRequested",
    "EmailVerificationRequested",
    "EmailVerified",
    "GenericOAuthProvider",
    "GenericOIDCProvider",
    "GoogleProvider",
    "GitHubProvider",
    "KeyRotated",
    "Login",
    "LoginFailed",
    "Logout",
    "MagicLinkLogin",
    "MagicLinkRequested",
    "OAuthLink",
    "PasswordChanged",
    "PasswordReset",
    "PasswordResetRequested",
    "RoleAdded",
    "RoleRemoved",
    "SessionResponse",
    "SessionRevoked",
    "TokenRefreshed",
    "UserBanned",
    "UserCreated",
    "UserResponse",
    "UserUnbanned",
    "UserUpdated",
    "alembic_exclude",
]
