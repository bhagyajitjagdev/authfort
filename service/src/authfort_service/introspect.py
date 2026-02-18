"""Token introspection client — calls the main AuthFort server for real-time validation.

Use this when you need to check banned status, token version, or fresh roles
that can't be determined from the JWT alone.
"""

import logging
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger("authfort_service.introspect")


@dataclass(frozen=True, slots=True)
class IntrospectionResult:
    """Result from the introspection endpoint."""

    active: bool
    sub: str | None = None
    email: str | None = None
    name: str | None = None
    roles: list[str] | None = None
    token_version: int | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None


class IntrospectionClient:
    """Async HTTP client for the AuthFort introspection endpoint.

    Args:
        introspect_url: URL of the introspection endpoint.
        secret: Shared secret for Authorization header (optional).
        cache_ttl: Cache TTL in seconds (0 = no cache, default).
        http_timeout: HTTP request timeout in seconds (default 5).
        fail_open: If True, return inactive on network errors instead of raising.
    """

    def __init__(
        self,
        introspect_url: str,
        *,
        secret: str | None = None,
        cache_ttl: float = 0.0,
        http_timeout: float = 5.0,
        fail_open: bool = False,
    ) -> None:
        self._introspect_url = introspect_url
        self._secret = secret
        self._cache_ttl = cache_ttl
        self._http_timeout = http_timeout
        self._fail_open = fail_open
        self._cache: dict[str, tuple[IntrospectionResult, float]] = {}

    async def introspect(self, token: str) -> IntrospectionResult:
        """Introspect a token via the auth server.

        Returns:
            IntrospectionResult with active=True/False.

        Raises:
            httpx.HTTPError: If auth server unreachable and fail_open is False.
        """
        if self._cache_ttl > 0:
            cached = self._cache.get(token)
            if cached is not None:
                result, cached_at = cached
                if (time.monotonic() - cached_at) < self._cache_ttl:
                    return result

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._secret:
            headers["Authorization"] = f"Bearer {self._secret}"

        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                response = await client.post(
                    self._introspect_url,
                    json={"token": token},
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
        except Exception:
            if self._fail_open:
                logger.warning(
                    "Introspection failed for %s, returning inactive",
                    self._introspect_url,
                )
                return IntrospectionResult(active=False)
            raise

        result = IntrospectionResult(
            active=data.get("active", False),
            sub=data.get("sub"),
            email=data.get("email"),
            name=data.get("name"),
            roles=data.get("roles"),
            token_version=data.get("token_version"),
            exp=data.get("exp"),
            iat=data.get("iat"),
            iss=data.get("iss"),
        )

        if self._cache_ttl > 0:
            self._cache[token] = (result, time.monotonic())
            if len(self._cache) > 1000:
                self._evict_stale()

        return result

    def _evict_stale(self) -> None:
        """Remove expired entries from the cache."""
        now = time.monotonic()
        stale = [k for k, (_, t) in self._cache.items() if (now - t) > self._cache_ttl]
        for k in stale:
            del self._cache[k]
