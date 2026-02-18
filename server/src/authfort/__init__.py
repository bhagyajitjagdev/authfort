"""AuthFort — Authentication and authorization library for Python."""

__version__ = "0.0.3"

from authfort.authfort import AuthFort
from authfort.config import CookieConfig
from authfort.core.auth import AuthError
from authfort.core.schemas import AuthResponse, SessionResponse, UserResponse
from authfort.providers.github import GitHubProvider
from authfort.providers.google import GoogleProvider

__all__ = ["AuthFort", "AuthError", "AuthResponse", "CookieConfig", "GoogleProvider", "GitHubProvider", "SessionResponse", "UserResponse"]
