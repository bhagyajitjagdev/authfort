"""JWKS fetcher and cache — fetches public keys from the auth server.

Features:
- TTL-based cache (configurable, default 1 hour)
- Auto-refresh on unknown kid (key rotation)
- Rate-limited refetch (max once per min_refetch_interval)
- Async-safe via asyncio.Lock
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

import httpx
from jwt import PyJWK

logger = logging.getLogger("authfort_service.jwks")


@dataclass
class CachedJWKS:
    """In-memory cache of JWKS keys."""

    keys: dict[str, PyJWK] = field(default_factory=dict)
    fetched_at: float = 0.0


class JWKSFetcher:
    """Fetches and caches JWKS public keys from the auth server.

    Args:
        jwks_url: URL of the JWKS endpoint.
        cache_ttl: How long to cache keys in seconds (default 3600 = 1 hour).
        min_refetch_interval: Minimum seconds between fetch attempts (default 30).
        http_timeout: HTTP request timeout in seconds (default 10).
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        cache_ttl: float = 3600.0,
        min_refetch_interval: float = 30.0,
        http_timeout: float = 10.0,
        _transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._jwks_url = jwks_url
        self._cache_ttl = cache_ttl
        self._min_refetch_interval = min_refetch_interval
        self._http_timeout = http_timeout
        self._transport = _transport
        self._cache = CachedJWKS()
        self._lock = asyncio.Lock()
        self._last_fetch_attempt: float = 0.0

    async def get_key(self, kid: str) -> PyJWK | None:
        """Get a public key by kid. Refreshes cache if stale."""
        key = self._cache.keys.get(kid)
        if key is not None and not self._is_cache_stale():
            return key
        await self._maybe_refresh()
        return self._cache.keys.get(kid)

    async def get_key_or_refresh(self, kid: str) -> PyJWK | None:
        """Get a key, forcing a refresh if kid is unknown (key rotation scenario)."""
        key = self._cache.keys.get(kid)
        if key is not None:
            return key
        await self._maybe_refresh(force=True)
        return self._cache.keys.get(kid)

    def _is_cache_stale(self) -> bool:
        if self._cache.fetched_at == 0.0:
            return True
        return (time.monotonic() - self._cache.fetched_at) > self._cache_ttl

    async def _maybe_refresh(self, *, force: bool = False) -> None:
        """Refresh the JWKS cache, respecting rate limits."""
        now = time.monotonic()
        if not force and not self._is_cache_stale():
            return
        if (now - self._last_fetch_attempt) < self._min_refetch_interval:
            return

        async with self._lock:
            now = time.monotonic()
            if (now - self._last_fetch_attempt) < self._min_refetch_interval:
                return
            self._last_fetch_attempt = now
            try:
                await self._fetch()
            except Exception:
                logger.exception("Failed to fetch JWKS from %s", self._jwks_url)

    async def _fetch(self) -> None:
        """Fetch JWKS from the server and update cache."""
        kwargs: dict = {"timeout": self._http_timeout}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(self._jwks_url)
            response.raise_for_status()
            jwks_data = response.json()

        new_keys: dict[str, PyJWK] = {}
        for key_data in jwks_data.get("keys", []):
            try:
                kid = key_data.get("kid")
                if kid:
                    new_keys[kid] = PyJWK(key_data)
            except Exception:
                logger.warning("Failed to parse JWK with kid=%s", key_data.get("kid"))

        self._cache = CachedJWKS(
            keys=new_keys,
            fetched_at=time.monotonic(),
        )
        logger.debug("JWKS refreshed: %d keys loaded", len(new_keys))
