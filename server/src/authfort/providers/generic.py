"""Generic OAuth 2.0 and OIDC providers — bring-your-own-provider support."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from authfort.core.auth import AuthError
from authfort.providers.base import OAuthProvider, OAuthUserInfo


def _default_map_user_info(
    provider_name: str, data: dict[str, Any], access_token: str,
) -> OAuthUserInfo:
    """Map a raw userinfo JSON response to OAuthUserInfo using common field names.

    Tries ``sub`` or ``id`` for the provider account ID, ``email`` for the email
    address, ``email_verified`` for verification status, ``name`` for the display
    name, and ``picture`` or ``avatar_url`` for the avatar.
    """
    account_id = data.get("sub") or data.get("id")
    if not account_id:
        raise AuthError(
            f"Could not determine user ID from {provider_name} response",
            code="oauth_no_user_id",
            status_code=400,
        )

    email = data.get("email")
    if not email:
        raise AuthError(
            f"Could not retrieve email from {provider_name}",
            code="oauth_no_email",
            status_code=400,
        )

    email_verified = bool(data.get("email_verified", False))
    name = data.get("name")
    avatar_url = data.get("picture") or data.get("avatar_url")

    return OAuthUserInfo(
        provider=provider_name,
        provider_account_id=str(account_id),
        email=email,
        email_verified=email_verified,
        name=name,
        avatar_url=avatar_url,
        access_token=access_token,
    )


MapUserInfoFn = Callable[[str, dict[str, Any], str], OAuthUserInfo]


@dataclass(frozen=True)
class GenericOAuthProvider(OAuthProvider):
    """Generic OAuth 2.0 provider — supply your own endpoints and optional mapper.

    Example::

        provider = GenericOAuthProvider(
            "gitlab",
            client_id="...",
            client_secret="...",
            authorize_url="https://gitlab.com/oauth/authorize",
            token_url="https://gitlab.com/oauth/token",
            userinfo_url="https://gitlab.com/api/v4/user",
            scopes=("read_user",),
        )
    """

    # These are declared to satisfy the dataclass field ordering (defaults after
    # non-defaults in the parent), but they are set via __init__ using
    # object.__setattr__ because the dataclass is frozen.
    _name: str = field(default="", repr=False, compare=False)
    _authorize_url: str = field(default="", repr=False, compare=False)
    _token_url: str = field(default="", repr=False, compare=False)
    userinfo_url: str = field(default="", compare=False)
    scopes_list: tuple[str, ...] = field(default=(), compare=False)
    map_user_info_fn: MapUserInfoFn | None = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        name: str,
        *,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        userinfo_url: str,
        scopes: tuple[str, ...] | list[str] = (),
        map_user_info: MapUserInfoFn | None = None,
        extra_scopes: tuple[str, ...] | list[str] = (),
        redirect_uri: str | None = None,
    ) -> None:
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "client_secret", client_secret)
        object.__setattr__(self, "extra_scopes", tuple(extra_scopes))
        object.__setattr__(self, "redirect_uri", redirect_uri)
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_authorize_url", authorize_url)
        object.__setattr__(self, "_token_url", token_url)
        object.__setattr__(self, "userinfo_url", userinfo_url)
        object.__setattr__(self, "scopes_list", tuple(scopes))
        object.__setattr__(self, "map_user_info_fn", map_user_info)

    @property
    def name(self) -> str:
        return self._name

    @property
    def authorize_url(self) -> str:
        return self._authorize_url

    @property
    def token_url(self) -> str:
        return self._token_url

    @property
    def scopes(self) -> tuple[str, ...]:
        """Combined scopes + extra_scopes, deduplicated and order-preserving."""
        seen: set[str] = set()
        result: list[str] = []
        for s in self.scopes_list + self.extra_scopes:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return tuple(result)

    async def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens via the token endpoint."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            response = await client.post(self._token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, *, access_token: str) -> OAuthUserInfo:
        """Fetch user profile from the userinfo endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            data = response.json()

        if self.map_user_info_fn is not None:
            return self.map_user_info_fn(self._name, data, access_token)
        return _default_map_user_info(self._name, data, access_token)


@dataclass(frozen=True)
class GenericOIDCProvider(OAuthProvider):
    """Generic OpenID Connect provider — auto-discovers endpoints from a discovery URL.

    Example::

        provider = GenericOIDCProvider(
            "keycloak",
            client_id="...",
            client_secret="...",
            discovery_url="https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration",
        )
    """

    _name: str = field(default="", repr=False, compare=False)
    _authorize_url: str = field(default="", repr=False, compare=False)
    _token_url: str = field(default="", repr=False, compare=False)
    discovery_url: str = field(default="", compare=False)
    scopes_list: tuple[str, ...] = field(default=(), compare=False)
    map_user_info_fn: MapUserInfoFn | None = field(default=None, repr=False, compare=False)
    discovery_ttl: float = field(default=3600, compare=False)
    _discovery_cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    _discovery_fetched_at: float = field(default=float("-inf"), repr=False, compare=False)

    def __init__(
        self,
        name: str,
        *,
        client_id: str,
        client_secret: str,
        discovery_url: str,
        scopes: tuple[str, ...] | list[str] = ("openid", "email", "profile"),
        map_user_info: MapUserInfoFn | None = None,
        discovery_ttl: float = 3600,
        extra_scopes: tuple[str, ...] | list[str] = (),
        redirect_uri: str | None = None,
    ) -> None:
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "client_secret", client_secret)
        object.__setattr__(self, "extra_scopes", tuple(extra_scopes))
        object.__setattr__(self, "redirect_uri", redirect_uri)
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_authorize_url", "")
        object.__setattr__(self, "_token_url", "")
        object.__setattr__(self, "discovery_url", discovery_url)
        object.__setattr__(self, "scopes_list", tuple(scopes))
        object.__setattr__(self, "map_user_info_fn", map_user_info)
        object.__setattr__(self, "discovery_ttl", discovery_ttl)
        object.__setattr__(self, "_discovery_cache", {})
        object.__setattr__(self, "_discovery_fetched_at", float("-inf"))

    @property
    def name(self) -> str:
        return self._name

    @property
    def authorize_url(self) -> str:
        if not self._authorize_url:
            raise RuntimeError(
                "OIDC discovery not yet fetched — call await provider._ensure_discovered() first"
            )
        return self._authorize_url

    @property
    def token_url(self) -> str:
        if not self._token_url:
            raise RuntimeError(
                "OIDC discovery not yet fetched — call await provider._ensure_discovered() first"
            )
        return self._token_url

    @property
    def scopes(self) -> tuple[str, ...]:
        """Combined scopes + extra_scopes, deduplicated and order-preserving."""
        seen: set[str] = set()
        result: list[str] = []
        for s in self.scopes_list + self.extra_scopes:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return tuple(result)

    async def _ensure_discovered(self) -> None:
        """Fetch the OIDC discovery document if the cache is stale."""
        now = time.monotonic()
        if now < self._discovery_fetched_at + self.discovery_ttl:
            return

        async with httpx.AsyncClient() as client:
            response = await client.get(self.discovery_url)
            response.raise_for_status()
            doc = response.json()

        object.__setattr__(self, "_discovery_cache", doc)
        object.__setattr__(self, "_discovery_fetched_at", now)
        object.__setattr__(self, "_authorize_url", doc["authorization_endpoint"])
        object.__setattr__(self, "_token_url", doc["token_endpoint"])

    async def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens via the discovered token endpoint."""
        await self._ensure_discovered()

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            response = await client.post(self._token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, *, access_token: str) -> OAuthUserInfo:
        """Fetch user profile from the discovered userinfo endpoint."""
        await self._ensure_discovered()

        userinfo_endpoint = self._discovery_cache["userinfo_endpoint"]

        async with httpx.AsyncClient() as client:
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            data = response.json()

        if self.map_user_info_fn is not None:
            return self.map_user_info_fn(self._name, data, access_token)
        return _default_map_user_info(self._name, data, access_token)
