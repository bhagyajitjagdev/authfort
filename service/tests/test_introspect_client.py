"""Tests for the introspection client — HTTP calls, caching, and error handling."""

import httpx
import pytest

from authfort_service.introspect import IntrospectionClient, IntrospectionResult

pytestmark = pytest.mark.asyncio


def _mock_introspect(response_data: dict, *, status_code: int = 200):
    """Create mock transport for introspection endpoint."""
    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(status_code, json=response_data)

    return handler, captured_requests


class TestIntrospectionClient:
    async def test_introspect_active_token(self, monkeypatch):
        response = {
            "active": True, "sub": "user-123", "email": "test@example.com",
            "roles": ["admin"], "token_version": 1, "exp": 99999, "iat": 11111,
            "iss": "authfort",
        }
        handler, _ = _mock_introspect(response)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient("http://test/auth/introspect")
        result = await client.introspect("some-token")

        assert isinstance(result, IntrospectionResult)
        assert result.active is True
        assert result.email == "test@example.com"
        assert result.roles == ["admin"]

    async def test_introspect_inactive_token(self, monkeypatch):
        handler, _ = _mock_introspect({"active": False})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient("http://test/auth/introspect")
        result = await client.introspect("bad-token")
        assert result.active is False

    async def test_introspect_sends_secret(self, monkeypatch):
        handler, captured = _mock_introspect({"active": True})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient(
            "http://test/auth/introspect", secret="my-secret",
        )
        await client.introspect("token")

        assert len(captured) == 1
        assert captured[0].headers["Authorization"] == "Bearer my-secret"

    async def test_introspect_cache(self, monkeypatch):
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, json={"active": True, "email": "test@example.com"})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient(
            "http://test/auth/introspect", cache_ttl=60,
        )
        await client.introspect("token-1")
        await client.introspect("token-1")  # Cached
        await client.introspect("token-1")  # Cached
        assert call_count["n"] == 1

    async def test_network_error_fail_open(self, monkeypatch):
        def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(error_handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient(
            "http://test/auth/introspect", fail_open=True,
        )
        result = await client.introspect("token")
        assert result.active is False

    async def test_network_error_fail_closed(self, monkeypatch):
        def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = httpx.MockTransport(error_handler)
            original_init(self_client, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

        client = IntrospectionClient(
            "http://test/auth/introspect", fail_open=False,
        )
        with pytest.raises(httpx.ConnectError):
            await client.introspect("token")
