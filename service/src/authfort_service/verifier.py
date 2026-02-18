"""JWT verification using JWKS public keys — local verification, no DB needed."""

import logging
from dataclasses import dataclass

import jwt

from authfort_service.jwks import JWKSFetcher

logger = logging.getLogger("authfort_service.verifier")


class TokenVerificationError(Exception):
    """Raised when JWT verification fails."""

    def __init__(self, message: str, code: str):
        self.message = message
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Decoded JWT payload — the user identity from a verified token."""

    sub: str
    email: str
    name: str | None
    roles: list[str]
    token_version: int
    exp: int
    iat: int
    iss: str


class JWTVerifier:
    """Verifies JWT access tokens using JWKS public keys.

    No database needed — pure cryptographic verification using cached public keys.

    Args:
        jwks_fetcher: The JWKS fetcher for key lookup.
        issuer: Expected JWT issuer claim (default "authfort").
        algorithms: Allowed JWT algorithms (default ["RS256"]).
    """

    def __init__(
        self,
        jwks_fetcher: JWKSFetcher,
        *,
        issuer: str = "authfort",
        algorithms: list[str] | None = None,
    ) -> None:
        self._fetcher = jwks_fetcher
        self._issuer = issuer
        self._algorithms = algorithms or ["RS256"]

    async def verify(self, token: str) -> TokenPayload:
        """Verify a JWT and return the decoded payload.

        Checks: signature, expiration, issuer, required claims.
        On unknown kid, triggers JWKS refresh (handles key rotation).

        Raises:
            TokenVerificationError: If verification fails.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise TokenVerificationError("Malformed token", "token_invalid")

        kid = header.get("kid")
        if not kid:
            raise TokenVerificationError("Token missing kid header", "token_invalid")

        jwk = await self._fetcher.get_key_or_refresh(kid)
        if jwk is None:
            raise TokenVerificationError("Unknown signing key", "token_invalid")

        try:
            payload = jwt.decode(
                token,
                jwk.key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                options={"require": ["sub", "email", "roles", "ver", "exp", "iat", "iss"]},
            )
        except jwt.ExpiredSignatureError:
            raise TokenVerificationError("Token has expired", "token_expired")
        except jwt.InvalidIssuerError:
            raise TokenVerificationError("Invalid issuer", "token_invalid")
        except jwt.InvalidTokenError as e:
            raise TokenVerificationError(f"Invalid token: {e}", "token_invalid")

        return TokenPayload(
            sub=payload["sub"],
            email=payload["email"],
            name=payload.get("name"),
            roles=payload["roles"],
            token_version=payload["ver"],
            exp=payload["exp"],
            iat=payload["iat"],
            iss=payload["iss"],
        )
