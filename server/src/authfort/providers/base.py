"""OAuth provider base class — defines the interface all providers must implement."""

from __future__ import annotations

import abc
import urllib.parse
from dataclasses import dataclass
from typing import Any, ClassVar


@dataclass(frozen=True, slots=True)
class OAuthUserInfo:
    """Normalized user info returned by any OAuth provider."""

    provider: str
    provider_account_id: str
    email: str
    email_verified: bool
    name: str | None = None
    avatar_url: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None


@dataclass(frozen=True)
class OAuthProvider(abc.ABC):
    """Abstract base for all OAuth providers.

    Subclasses must implement:
        name            — provider identifier (e.g. "google", "github")
        authorize_url   — provider's authorization endpoint
        token_url       — provider's token exchange endpoint
        exchange_code() — exchange auth code for tokens
        get_user_info() — fetch user profile from provider
    """

    client_id: str
    client_secret: str
    extra_scopes: tuple[str, ...] = ()
    redirect_uri: str | None = None

    REQUIRED_SCOPES: ClassVar[tuple[str, ...]] = ()

    @property
    @abc.abstractmethod
    def name(self) -> str: ...

    @property
    @abc.abstractmethod
    def authorize_url(self) -> str: ...

    @property
    @abc.abstractmethod
    def token_url(self) -> str: ...

    @property
    def scopes(self) -> tuple[str, ...]:
        """Combined required + extra scopes (deduplicated, order-preserving)."""
        seen: set[str] = set()
        result: list[str] = []
        for s in self.REQUIRED_SCOPES + self.extra_scopes:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return tuple(result)

    def get_authorization_url(
        self, *, redirect_uri: str, state: str, code_challenge: str | None = None,
    ) -> str:
        """Build the full authorization URL with query params.

        Default implementation works for standard OAuth 2.0 providers.
        Includes PKCE code_challenge (S256) when provided.
        Subclasses can override for provider-specific params.
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes),
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorize_url}?{urllib.parse.urlencode(params)}"

    @abc.abstractmethod
    async def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for provider tokens.

        Args:
            code: The authorization code from the callback.
            redirect_uri: Must match the one used in the authorize request.
            code_verifier: PKCE code verifier (required by OAuth 2.1).

        Returns raw token response dict from the provider.
        """
        ...

    @abc.abstractmethod
    async def get_user_info(self, *, access_token: str) -> OAuthUserInfo:
        """Fetch user profile from the provider API.

        Returns normalized OAuthUserInfo.
        """
        ...
