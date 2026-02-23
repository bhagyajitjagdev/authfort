"""AuthFort OAuth providers."""

from authfort.providers.base import OAuthProvider, OAuthUserInfo
from authfort.providers.generic import GenericOAuthProvider, GenericOIDCProvider
from authfort.providers.github import GitHubProvider
from authfort.providers.google import GoogleProvider

__all__ = [
    "OAuthProvider",
    "OAuthUserInfo",
    "GoogleProvider",
    "GitHubProvider",
    "GenericOAuthProvider",
    "GenericOIDCProvider",
]
