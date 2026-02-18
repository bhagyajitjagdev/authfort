"""Google OAuth 2.0 provider."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from authfort.providers.base import OAuthProvider, OAuthUserInfo


@dataclass(frozen=True)
class GoogleProvider(OAuthProvider):
    """Google OAuth provider.

    Default scopes: openid, email, profile.
    """

    scopes: tuple[str, ...] = ("openid", "email", "profile")

    @property
    def name(self) -> str:
        return "google"

    @property
    def authorize_url(self) -> str:
        return "https://accounts.google.com/o/oauth2/v2/auth"

    @property
    def token_url(self) -> str:
        return "https://oauth2.googleapis.com/token"

    def get_authorization_url(
        self, *, redirect_uri: str, state: str, code_challenge: str | None = None,
    ) -> str:
        """Google-specific: adds access_type=offline and prompt=consent."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes),
            "access_type": "offline",
            "prompt": "consent",
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorize_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for Google tokens."""
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
            response = await client.post(self.token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, *, access_token: str) -> OAuthUserInfo:
        """Fetch Google user profile from userinfo endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            data = response.json()

        return OAuthUserInfo(
            provider="google",
            provider_account_id=data["id"],
            email=data["email"],
            email_verified=data.get("verified_email", False),
            name=data.get("name"),
            avatar_url=data.get("picture"),
            access_token=access_token,
        )
