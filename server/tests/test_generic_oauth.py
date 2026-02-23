"""Tests for GenericOAuthProvider and GenericOIDCProvider."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from authfort.core.auth import AuthError
from authfort.providers.base import OAuthUserInfo
from authfort.providers.generic import (
    GenericOAuthProvider,
    GenericOIDCProvider,
    _default_map_user_info,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_DISCOVERY = {
    "authorization_endpoint": "https://keycloak.example.com/auth",
    "token_endpoint": "https://keycloak.example.com/token",
    "userinfo_endpoint": "https://keycloak.example.com/userinfo",
    "issuer": "https://keycloak.example.com",
}


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


def _make_mock_client(
    *, post_response: MagicMock | None = None, get_response: MagicMock | None = None,
    get_side_effect: list[MagicMock] | None = None,
) -> AsyncMock:
    """Build a mock httpx.AsyncClient with common boilerplate."""
    mock_client = AsyncMock()
    if post_response is not None:
        mock_client.post = AsyncMock(return_value=post_response)
    if get_response is not None:
        mock_client.get = AsyncMock(return_value=get_response)
    if get_side_effect is not None:
        mock_client.get = AsyncMock(side_effect=get_side_effect)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def _gitlab_provider(**kwargs) -> GenericOAuthProvider:
    defaults = dict(
        client_id="test-id",
        client_secret="test-secret",
        authorize_url="https://gitlab.com/oauth/authorize",
        token_url="https://gitlab.com/oauth/token",
        userinfo_url="https://gitlab.com/api/v4/user",
        scopes=("read_user",),
    )
    defaults.update(kwargs)
    return GenericOAuthProvider("gitlab", **defaults)


def _keycloak_provider(**kwargs) -> GenericOIDCProvider:
    defaults = dict(
        client_id="test-id",
        client_secret="test-secret",
        discovery_url="https://keycloak.example.com/.well-known/openid-configuration",
    )
    defaults.update(kwargs)
    return GenericOIDCProvider("keycloak", **defaults)


# ---------------------------------------------------------------------------
# GenericOAuthProvider
# ---------------------------------------------------------------------------


class TestGenericOAuthProvider:
    """Unit tests for GenericOAuthProvider."""

    async def test_name_property(self):
        provider = _gitlab_provider()
        assert provider.name == "gitlab"

    async def test_authorize_url_property(self):
        provider = _gitlab_provider()
        assert provider.authorize_url == "https://gitlab.com/oauth/authorize"

    async def test_token_url_property(self):
        provider = _gitlab_provider()
        assert provider.token_url == "https://gitlab.com/oauth/token"

    async def test_scopes_deduplication(self):
        provider = _gitlab_provider(scopes=("a", "b"), extra_scopes=("b", "c"))
        assert provider.scopes == ("a", "b", "c")

    async def test_get_authorization_url(self):
        provider = _gitlab_provider()
        url = provider.get_authorization_url(
            redirect_uri="http://localhost/callback",
            state="s1",
        )
        assert "client_id=test-id" in url
        assert "redirect_uri=http" in url
        assert "response_type=code" in url
        assert "state=s1" in url
        assert "scope=read_user" in url
        assert url.startswith("https://gitlab.com/oauth/authorize?")

    async def test_get_authorization_url_with_pkce(self):
        provider = _gitlab_provider()
        url = provider.get_authorization_url(
            redirect_uri="http://localhost/callback",
            state="s1",
            code_challenge="abc123",
        )
        assert "code_challenge=abc123" in url
        assert "code_challenge_method=S256" in url

    async def test_exchange_code(self):
        provider = _gitlab_provider()
        token_data = {"access_token": "tok123", "token_type": "Bearer"}
        mock_client = _make_mock_client(post_response=_mock_response(token_data))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            result = await provider.exchange_code(
                code="abc", redirect_uri="http://localhost/callback",
            )

        assert result["access_token"] == "tok123"
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        post_data = call_args[1].get("data") or call_args[0][1] if len(call_args[0]) > 1 else call_args[1]["data"]
        assert post_data["client_id"] == "test-id"
        assert post_data["client_secret"] == "test-secret"
        assert post_data["code"] == "abc"
        assert post_data["grant_type"] == "authorization_code"
        assert post_data["redirect_uri"] == "http://localhost/callback"

    async def test_get_user_info_default_mapping(self):
        provider = _gitlab_provider()
        userinfo_data = {
            "sub": "123",
            "email": "a@b.com",
            "name": "Test",
            "email_verified": True,
            "picture": "http://pic.jpg",
        }
        mock_client = _make_mock_client(get_response=_mock_response(userinfo_data))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok-abc")

        assert isinstance(info, OAuthUserInfo)
        assert info.provider == "gitlab"
        assert info.provider_account_id == "123"
        assert info.email == "a@b.com"
        assert info.email_verified is True
        assert info.name == "Test"
        assert info.avatar_url == "http://pic.jpg"
        assert info.access_token == "tok-abc"

    async def test_get_user_info_custom_mapper(self):
        custom_mapper = MagicMock(
            return_value=OAuthUserInfo(
                provider="gitlab",
                provider_account_id="custom-id",
                email="custom@test.com",
                email_verified=True,
                access_token="tok",
            ),
        )
        provider = _gitlab_provider(map_user_info=custom_mapper)
        userinfo_data = {"sub": "123", "email": "a@b.com"}
        mock_client = _make_mock_client(get_response=_mock_response(userinfo_data))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            info = await provider.get_user_info(access_token="tok")

        custom_mapper.assert_called_once_with("gitlab", userinfo_data, "tok")
        assert info.provider_account_id == "custom-id"
        assert info.email == "custom@test.com"

    async def test_default_mapper_missing_email_raises(self):
        with pytest.raises(AuthError, match="Could not retrieve email") as exc_info:
            _default_map_user_info("gitlab", {"sub": "123"}, "tok")
        assert exc_info.value.code == "oauth_no_email"

    async def test_default_mapper_missing_id_raises(self):
        with pytest.raises(AuthError, match="Could not determine user ID") as exc_info:
            _default_map_user_info("gitlab", {"email": "a@b.com"}, "tok")
        assert exc_info.value.code == "oauth_no_user_id"


# ---------------------------------------------------------------------------
# GenericOIDCProvider
# ---------------------------------------------------------------------------


class TestGenericOIDCProvider:
    """Unit tests for GenericOIDCProvider."""

    async def test_discovery_fetch_and_cache(self):
        provider = _keycloak_provider()
        mock_client = _make_mock_client(get_response=_mock_response(MOCK_DISCOVERY))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            await provider._ensure_discovered()

        # After discovery, the endpoints should be populated
        assert provider.authorize_url == "https://keycloak.example.com/auth"
        assert provider.token_url == "https://keycloak.example.com/token"
        mock_client.get.assert_called_once()

    async def test_discovery_cache_within_ttl(self):
        provider = _keycloak_provider()
        mock_client = _make_mock_client(get_response=_mock_response(MOCK_DISCOVERY))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            await provider._ensure_discovered()
            await provider._ensure_discovered()

        # Should only fetch once because the cache is still valid
        mock_client.get.assert_called_once()

    async def test_discovery_cache_expiry(self):
        provider = _keycloak_provider()
        mock_client = _make_mock_client(get_response=_mock_response(MOCK_DISCOVERY))

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            await provider._ensure_discovered()
            assert mock_client.get.call_count == 1

            # Force cache expiry by setting fetched_at to distant past
            object.__setattr__(provider, "_discovery_fetched_at", float("-inf"))

            await provider._ensure_discovered()
            assert mock_client.get.call_count == 2

    async def test_authorize_url_before_discovery_raises(self):
        provider = _keycloak_provider()
        with pytest.raises(RuntimeError, match="OIDC discovery not yet fetched"):
            _ = provider.authorize_url

    async def test_token_url_before_discovery_raises(self):
        provider = _keycloak_provider()
        with pytest.raises(RuntimeError, match="OIDC discovery not yet fetched"):
            _ = provider.token_url

    async def test_exchange_code_uses_discovered_endpoint(self):
        provider = _keycloak_provider()
        token_data = {"access_token": "oidc-tok", "id_token": "id-tok"}

        # Discovery GET followed by token POST — both use the same mock client
        mock_client = _make_mock_client(
            get_response=_mock_response(MOCK_DISCOVERY),
            post_response=_mock_response(token_data),
        )

        with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
            result = await provider.exchange_code(
                code="oidc-code", redirect_uri="http://localhost/callback",
            )

        assert result["access_token"] == "oidc-tok"
        # Verify the POST was sent to the discovered token endpoint
        mock_client.post.assert_called_once()
        post_url = mock_client.post.call_args[0][0]
        assert post_url == "https://keycloak.example.com/token"

    async def test_default_scopes(self):
        provider = _keycloak_provider()
        assert provider.scopes == ("openid", "email", "profile")


# ---------------------------------------------------------------------------
# OAuth Router — OIDC discovery pre-fetch
# ---------------------------------------------------------------------------


class TestOIDCRouterDiscovery:
    async def test_authorize_calls_ensure_discovered(self):
        """The OAuth router pre-fetches OIDC discovery before generating the auth URL."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from authfort import AuthFort, CookieConfig
        from conftest import TEST_DATABASE_URL

        provider = _keycloak_provider()

        auth = AuthFort(
            database_url=TEST_DATABASE_URL,
            cookie=CookieConfig(secure=False),
            providers=[provider],
        )
        await auth.migrate()

        app = FastAPI()
        app.include_router(auth.fastapi_router(), prefix="/auth")

        mock_client = _make_mock_client(
            get_response=_mock_response(MOCK_DISCOVERY),
        )

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            with patch("authfort.providers.generic.httpx.AsyncClient", return_value=mock_client):
                response = await client.get("/auth/oauth/keycloak/authorize")

        assert response.status_code == 302
        assert "keycloak.example.com/auth" in response.headers["location"]
        await auth.dispose()
