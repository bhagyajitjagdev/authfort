"""FastAPI JWKS router — serves public keys at /.well-known/jwks.json."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.keys import public_key_to_jwk
from authfort.repositories import signing_key as signing_key_repo


def create_jwks_router(config: AuthFortConfig, get_db: Callable) -> APIRouter:
    """Create a FastAPI router serving the JWKS endpoint.

    Mount at the root (no prefix) so the endpoint is at /.well-known/jwks.json.
    """
    router = APIRouter(tags=["jwks"])

    @router.get("/.well-known/jwks.json")
    async def jwks_endpoint(
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Serve all non-expired public keys as a JWK Set (RFC 7517)."""
        keys = await signing_key_repo.get_non_expired_signing_keys(session)
        jwk_set = {
            "keys": [
                public_key_to_jwk(k.kid, k.public_key, k.algorithm)
                for k in keys
            ]
        }
        return JSONResponse(
            content=jwk_set,
            headers={
                "Cache-Control": "public, max-age=3600",
            },
        )

    return router
