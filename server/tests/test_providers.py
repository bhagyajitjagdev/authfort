"""Tests for OAuth providers with mocked HTTP calls."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from authfort.core.auth import AuthError
from authfort.providers.base import OAuthUserInfo
from authfort.providers.github import GitHubProvider
from authfort.providers.google import GoogleProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp,
        )
    return resp


# ---------------------------------------------------------------------------
# Google Provider
# ---------------------------------------------------------------------------


class TestGoogleProvider:
    """Test GoogleProvider with mocked httpx."""

    def _provider(self, **kwargs) -> GoogleProvider:
        return GoogleProvider(
            client_id="google-client-id",
            client_secret="google-client-secret",
            **kwargs,
        )

    async def test_exchange_code(self):
        provider = self._provider()
        token_response = {
            "access_token": "ya29.test-access-token",
            "refresh_token": "1//test-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(token_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            result = await provider.exchange_code(
                code="auth-code-123",
                redirect_uri="http://localhost/callback",
            )

        assert result["access_token"] == "ya29.test-access-token"
        assert result["refresh_token"] == "1//test-refresh-token"
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["data"]["client_id"] == "google-client-id"
        assert call_kwargs[1]["data"]["code"] == "auth-code-123"

    async def test_exchange_code_with_pkce(self):
        provider = self._provider()
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({"access_token": "tok"})
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            await provider.exchange_code(
                code="code", redirect_uri="http://localhost/cb",
                code_verifier="verifier-123",
            )

        call_data = mock_client.post.call_args[1]["data"]
        assert call_data["code_verifier"] == "verifier-123"

    async def test_get_user_info(self):
        provider = self._provider()
        userinfo_response = {
            "id": "google-uid-123",
            "email": "user@gmail.com",
            "verified_email": True,
            "name": "Test User",
            "picture": "https://lh3.googleusercontent.com/photo.jpg",
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(userinfo_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="ya29.test-token")

        assert isinstance(info, OAuthUserInfo)
        assert info.provider == "google"
        assert info.provider_account_id == "google-uid-123"
        assert info.email == "user@gmail.com"
        assert info.email_verified is True
        assert info.name == "Test User"
        assert info.avatar_url == "https://lh3.googleusercontent.com/photo.jpg"
        assert info.access_token == "ya29.test-token"

    async def test_get_user_info_unverified_email(self):
        provider = self._provider()
        userinfo_response = {
            "id": "123",
            "email": "user@gmail.com",
            "verified_email": False,
            "name": "User",
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(userinfo_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email_verified is False

    async def test_get_user_info_no_picture(self):
        provider = self._provider()
        userinfo_response = {
            "id": "123",
            "email": "user@gmail.com",
            "verified_email": True,
            "name": "User",
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(userinfo_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.avatar_url is None

    async def test_authorization_url_includes_google_specifics(self):
        provider = self._provider()
        url = provider.get_authorization_url(
            redirect_uri="http://localhost/callback",
            state="test-state",
        )
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "accounts.google.com" in url

    async def test_authorization_url_with_pkce(self):
        provider = self._provider()
        url = provider.get_authorization_url(
            redirect_uri="http://localhost/callback",
            state="test-state",
            code_challenge="challenge-abc",
        )
        assert "code_challenge=challenge-abc" in url
        assert "code_challenge_method=S256" in url

    async def test_exchange_code_http_error(self):
        provider = self._provider()
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({}, status_code=400)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.google.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await provider.exchange_code(
                    code="bad-code", redirect_uri="http://localhost/cb",
                )


# ---------------------------------------------------------------------------
# GitHub Provider
# ---------------------------------------------------------------------------


class TestGitHubProvider:
    """Test GitHubProvider with mocked httpx."""

    def _provider(self, **kwargs) -> GitHubProvider:
        return GitHubProvider(
            client_id="gh-client-id",
            client_secret="gh-client-secret",
            **kwargs,
        )

    async def test_exchange_code(self):
        provider = self._provider()
        token_response = {
            "access_token": "gho_test_access_token",
            "token_type": "bearer",
            "scope": "read:user,user:email",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(token_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            result = await provider.exchange_code(
                code="gh-auth-code",
                redirect_uri="http://localhost/callback",
            )

        assert result["access_token"] == "gho_test_access_token"
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["data"]["client_id"] == "gh-client-id"
        assert call_kwargs[1]["headers"]["Accept"] == "application/json"

    async def test_exchange_code_with_pkce(self):
        provider = self._provider()
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({"access_token": "tok"})
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            await provider.exchange_code(
                code="code", redirect_uri="http://localhost/cb",
                code_verifier="pkce-verifier",
            )

        call_data = mock_client.post.call_args[1]["data"]
        assert call_data["code_verifier"] == "pkce-verifier"

    async def test_get_user_info_public_email_verified(self):
        """GitHub user with public email that is verified."""
        provider = self._provider()
        user_data = {
            "id": 12345,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@github.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/12345",
        }
        emails_data = [
            {"email": "octocat@github.com", "primary": True, "verified": True},
            {"email": "alt@example.com", "primary": False, "verified": True},
        ]

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="gho_token")

        assert info.provider == "github"
        assert info.provider_account_id == "12345"
        assert info.email == "octocat@github.com"
        assert info.email_verified is True
        assert info.name == "The Octocat"
        assert info.avatar_url == "https://avatars.githubusercontent.com/u/12345"

    async def test_get_user_info_public_email_unverified(self):
        """GitHub user with public email that is NOT verified."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "email": "user@example.com"}
        emails_data = [
            {"email": "user@example.com", "primary": True, "verified": False},
        ]

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email == "user@example.com"
        assert info.email_verified is False

    async def test_get_user_info_private_email_primary_verified(self):
        """GitHub user with private email — falls back to primary verified email."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": None, "email": None}
        emails_data = [
            {"email": "private@users.noreply.github.com", "primary": False, "verified": True},
            {"email": "real@example.com", "primary": True, "verified": True},
        ]

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email == "real@example.com"
        assert info.email_verified is True
        # Falls back to login when name is None
        assert info.name == "user"

    async def test_get_user_info_private_email_fallback_any_verified(self):
        """No primary verified email — falls back to any verified email."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": "User", "email": None}
        emails_data = [
            {"email": "unverified@example.com", "primary": True, "verified": False},
            {"email": "verified@example.com", "primary": False, "verified": True},
        ]

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email == "verified@example.com"
        assert info.email_verified is True

    async def test_get_user_info_private_email_last_resort(self):
        """No verified emails — uses first available email."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": "User", "email": None}
        emails_data = [
            {"email": "only@example.com", "primary": False, "verified": False},
        ]

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email == "only@example.com"
        assert info.email_verified is False

    async def test_get_user_info_no_email_at_all(self):
        """No email available anywhere — raises AuthError."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": "User", "email": None}
        emails_data = []

        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(user_data),
            _mock_response(emails_data),
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(AuthError, match="Could not retrieve email"):
                await provider.get_user_info(access_token="tok")

    async def test_get_user_info_emails_endpoint_fails(self):
        """Emails endpoint returns non-200 and user has no public email."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": "User", "email": None}

        mock_client = AsyncMock()
        failed_emails_resp = _mock_response({}, status_code=403)
        mock_client.get.side_effect = [
            _mock_response(user_data),
            failed_emails_resp,
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(AuthError, match="Could not retrieve email"):
                await provider.get_user_info(access_token="tok")

    async def test_get_user_info_emails_endpoint_fails_but_public_email(self):
        """Emails endpoint fails but user has public email — email_verified stays False."""
        provider = self._provider()
        user_data = {"id": 1, "login": "user", "name": "User", "email": "pub@example.com"}

        mock_client = AsyncMock()
        failed_emails_resp = _mock_response({}, status_code=403)
        mock_client.get.side_effect = [
            _mock_response(user_data),
            failed_emails_resp,
        ]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        assert info.email == "pub@example.com"
        assert info.email_verified is False

    async def test_exchange_code_http_error(self):
        provider = self._provider()
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({}, status_code=401)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("authfort.providers.github.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await provider.exchange_code(
                    code="bad-code", redirect_uri="http://localhost/cb",
                )

    async def test_properties(self):
        provider = self._provider()
        assert provider.name == "github"
        assert "github.com" in provider.authorize_url
        assert "github.com" in provider.token_url
