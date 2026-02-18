"""Tests for the JWKS fetcher — caching, refresh, and error handling."""

import logging

import httpx
import pytest

from authfort_service.jwks import JWKSFetcher

pytestmark = pytest.mark.asyncio


def _make_mock_transport(jwks_response: dict, *, status_code: int = 200):
    """Create an httpx MockTransport that returns the given JWKS response."""
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(status_code, json=jwks_response)

    return httpx.MockTransport(handler), call_count


class TestJWKSFetcher:
    async def test_fetch_and_cache_keys(self, jwks_response, test_kid):
        transport, call_count = _make_mock_transport(jwks_response)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            cache_ttl=3600,
            _transport=transport,
        )

        key = await fetcher.get_key(test_kid)
        assert key is not None
        assert call_count["n"] == 1

    async def test_cache_prevents_refetch(self, jwks_response, test_kid):
        transport, call_count = _make_mock_transport(jwks_response)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            cache_ttl=3600,
            _transport=transport,
        )

        await fetcher.get_key(test_kid)
        await fetcher.get_key(test_kid)
        await fetcher.get_key(test_kid)
        assert call_count["n"] == 1  # Only one fetch

    async def test_unknown_kid_triggers_refresh(self, jwks_response, test_kid):
        transport, call_count = _make_mock_transport(jwks_response)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            cache_ttl=3600,
            min_refetch_interval=0,
            _transport=transport,
        )

        await fetcher.get_key(test_kid)
        result = await fetcher.get_key_or_refresh("unknown-kid")
        assert result is None
        assert call_count["n"] == 2  # Second fetch attempted

    async def test_rate_limiting(self, jwks_response, test_kid):
        transport, call_count = _make_mock_transport(jwks_response)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            cache_ttl=0,  # Always stale
            min_refetch_interval=60,  # Rate limit 60s
            _transport=transport,
        )

        await fetcher.get_key(test_kid)  # First fetch
        await fetcher.get_key(test_kid)  # Rate limited, no fetch
        assert call_count["n"] == 1

    async def test_fetch_failure_logged(self, test_kid, caplog):
        def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        transport = httpx.MockTransport(error_handler)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            _transport=transport,
        )

        with caplog.at_level(logging.ERROR, logger="authfort_service.jwks"):
            result = await fetcher.get_key(test_kid)
        assert result is None
        assert "Failed to fetch JWKS" in caplog.text

    async def test_malformed_jwk_skipped(self, test_kid):
        jwks_with_bad_key = {
            "keys": [
                {"kty": "invalid", "kid": "bad-key"},
            ]
        }
        transport, _ = _make_mock_transport(jwks_with_bad_key)
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            _transport=transport,
        )

        result = await fetcher.get_key("bad-key")
        assert result is None  # Bad key should be skipped

    async def test_empty_jwks_response(self):
        transport, _ = _make_mock_transport({"keys": []})
        fetcher = JWKSFetcher(
            "http://test/.well-known/jwks.json",
            _transport=transport,
        )

        result = await fetcher.get_key("any-kid")
        assert result is None
