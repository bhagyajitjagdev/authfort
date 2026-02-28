"""AuthFort — Authentication and authorization library for Python."""

__version__ = "0.0.16"

from authfort.alembic_helper import alembic_filters, register_foreign_tables
from authfort.authfort import AuthFort
from authfort.config import CookieConfig, RateLimitConfig
from authfort.core.auth import AuthError
from authfort.core.schemas import AuthResponse, AuthTokens, ListUsersResponse, SessionResponse, UserResponse
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
    RateLimitExceeded,
    RoleAdded,
    RoleRemoved,
    SessionRevoked,
    TokenRefreshed,
    UserBanned,
    UserCreated,
    UserDeleted,
    UserUnbanned,
    UserUpdated,
)
from authfort.models.user import User as AuthUser
from authfort.models.user_role import UserRole as AuthUserRole
from authfort.providers.generic import GenericOAuthProvider, GenericOIDCProvider
from authfort.providers.github import GitHubProvider
from authfort.providers.google import GoogleProvider

__all__ = [
    "AuthFort",
    "AuthError",
    "AuthUser",
    "AuthUserRole",
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
    "ListUsersResponse",
    "Login",
    "LoginFailed",
    "Logout",
    "MagicLinkLogin",
    "MagicLinkRequested",
    "OAuthLink",
    "PasswordChanged",
    "PasswordReset",
    "PasswordResetRequested",
    "RateLimitConfig",
    "RateLimitExceeded",
    "RoleAdded",
    "RoleRemoved",
    "SessionResponse",
    "SessionRevoked",
    "TokenRefreshed",
    "UserBanned",
    "UserCreated",
    "UserDeleted",
    "UserResponse",
    "UserUnbanned",
    "UserUpdated",
    "alembic_filters",
    "register_foreign_tables",
]
