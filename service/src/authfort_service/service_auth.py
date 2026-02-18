"""ServiceAuth — main entry point for authfort-service.

Mirrors AuthFort's API style with .current_user and .require_role() dependencies.
No database needed — verifies JWTs using cached JWKS public keys.
"""

from authfort_service.introspect import IntrospectionClient, IntrospectionResult
from authfort_service.jwks import JWKSFetcher
from authfort_service.verifier import JWTVerifier, TokenPayload, TokenVerificationError


class ServiceAuth:
    """Lightweight JWT verifier for microservices.

    Verifies AuthFort-issued JWTs using JWKS public keys.
    Optionally introspects tokens for real-time checks (banned, version mismatch).

    Args:
        jwks_url: URL of the AuthFort JWKS endpoint.
        issuer: Expected JWT issuer claim (default "authfort").
        algorithms: Allowed JWT algorithms (default ["RS256"]).
        jwks_cache_ttl: How long to cache JWKS keys in seconds (default 3600).
        introspect_url: URL of the introspection endpoint (optional).
        introspect_secret: Shared secret for introspection auth (optional).
        introspect_cache_ttl: Cache TTL for introspection results (default 0 = no cache).
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        issuer: str = "authfort",
        algorithms: list[str] | None = None,
        jwks_cache_ttl: float = 3600.0,
        introspect_url: str | None = None,
        introspect_secret: str | None = None,
        introspect_cache_ttl: float = 0.0,
    ) -> None:
        self._jwks_fetcher = JWKSFetcher(jwks_url, cache_ttl=jwks_cache_ttl)
        self._verifier = JWTVerifier(
            self._jwks_fetcher, issuer=issuer, algorithms=algorithms,
        )
        self._introspect_client: IntrospectionClient | None = None
        if introspect_url is not None:
            self._introspect_client = IntrospectionClient(
                introspect_url,
                secret=introspect_secret,
                cache_ttl=introspect_cache_ttl,
                fail_open=True,
            )
        self._current_user_dep = None

    async def verify_token(self, token: str) -> TokenPayload:
        """Verify a JWT and return the decoded payload (JWKS-only, no introspection).

        Raises:
            TokenVerificationError: If verification fails.
        """
        return await self._verifier.verify(token)

    async def introspect(self, token: str) -> IntrospectionResult:
        """Introspect a token via the auth server (real-time check).

        Raises:
            RuntimeError: If introspection is not configured.
        """
        if self._introspect_client is None:
            raise RuntimeError(
                "Introspection not configured. Pass introspect_url to ServiceAuth()."
            )
        return await self._introspect_client.introspect(token)

    @property
    def current_user(self):
        """FastAPI dependency: get the current authenticated user from JWT.

        Uses JWKS-only verification (fast, no network call to auth server).

        Usage:
            service_auth = ServiceAuth(jwks_url="...")

            @app.get("/profile")
            async def profile(user=Depends(service_auth.current_user)):
                print(user.email)
        """
        if self._current_user_dep is None:
            from authfort_service.integrations.fastapi import create_current_user_dep

            self._current_user_dep = create_current_user_dep(self._verifier)
        return self._current_user_dep

    def require_role(self, role: str | list[str]):
        """FastAPI dependency factory: require a specific role.

        Usage:
            @app.get("/admin")
            async def admin(user=Depends(service_auth.require_role("admin"))):
                ...
        """
        from authfort_service.integrations.fastapi import create_require_role_dep

        return create_require_role_dep(self._verifier, role)
