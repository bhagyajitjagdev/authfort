"""GitHub OAuth 2.0 provider."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

import httpx

from authfort.core.auth import AuthError
from authfort.providers.base import OAuthProvider, OAuthUserInfo


@dataclass(frozen=True)
class GitHubProvider(OAuthProvider):
    """GitHub OAuth provider.

    Required scopes: read:user, user:email.
    Pass ``extra_scopes`` to request additional permissions.
    """

    REQUIRED_SCOPES: ClassVar[tuple[str, ...]] = ("read:user", "user:email")

    @property
    def name(self) -> str:
        return "github"

    @property
    def authorize_url(self) -> str:
        return "https://github.com/login/oauth/authorize"

    @property
    def token_url(self) -> str:
        return "https://github.com/login/oauth/access_token"

    async def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for GitHub tokens.

        GitHub requires Accept: application/json to get JSON response.
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url, data=data, headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, *, access_token: str) -> OAuthUserInfo:
        """Fetch GitHub user profile and primary email.

        GitHub may not return email in /user if it's private.
        Falls back to /user/emails to find the primary verified email.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient() as client:
            # Get user profile
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            user_resp.raise_for_status()
            user_data = user_resp.json()

            email = user_data.get("email")
            email_verified = False

            # Fetch emails endpoint for verification status and private email fallback
            emails_resp = await client.get("https://api.github.com/user/emails", headers=headers)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()

                if email:
                    # Check if the public email is verified
                    for entry in emails:
                        if entry["email"] == email and entry.get("verified"):
                            email_verified = True
                            break
                else:
                    # Find primary verified email
                    for entry in emails:
                        if entry.get("primary") and entry.get("verified"):
                            email = entry["email"]
                            email_verified = True
                            break

                    # Fallback: any verified email
                    if not email:
                        for entry in emails:
                            if entry.get("verified"):
                                email = entry["email"]
                                email_verified = True
                                break

                    # Last resort: any email
                    if not email and emails:
                        email = emails[0]["email"]

        if not email:
            raise AuthError(
                "Could not retrieve email from GitHub",
                code="oauth_no_email",
                status_code=400,
            )

        return OAuthUserInfo(
            provider="github",
            provider_account_id=str(user_data["id"]),
            email=email,
            email_verified=email_verified,
            name=user_data.get("name") or user_data.get("login"),
            avatar_url=user_data.get("avatar_url"),
            access_token=access_token,
        )
