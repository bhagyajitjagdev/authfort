"""FastAPI introspection router — RFC 7662 compatible token introspection."""

import hmac
import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.tokens import get_unverified_header, verify_access_token
from authfort.repositories import role as role_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo


class IntrospectRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    email: str | None = None
    name: str | None = None
    roles: list[str] | None = None
    token_version: int | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None


def create_introspect_router(config: AuthFortConfig, get_db: Callable) -> APIRouter:
    """Create a FastAPI router with the introspection endpoint.

    If config.introspect_secret is set, the endpoint requires
    Authorization: Bearer <secret> for access.
    """
    router = APIRouter(tags=["introspection"])
    _inactive = IntrospectResponse(active=False)

    def _check_auth(request: Request) -> None:
        """Verify the introspection request is authorized (if secret is configured)."""
        if config.introspect_secret is None:
            return
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail={"error": "unauthorized", "message": "Missing or invalid Authorization header"},
            )
        provided = auth_header[7:]
        if not hmac.compare_digest(provided, config.introspect_secret):
            raise HTTPException(
                status_code=401,
                detail={"error": "unauthorized", "message": "Invalid introspection secret"},
            )

    @router.post("/introspect", response_model=IntrospectResponse)
    async def introspect_endpoint(
        data: IntrospectRequest,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Introspect a token — full verification including DB checks.

        Returns RFC 7662 compatible response with active=true/false.
        Performs: signature check, expiration, token_version, banned check.
        """
        _check_auth(request)

        # Extract kid from header
        try:
            header = get_unverified_header(data.token)
        except Exception:
            return _inactive

        kid = header.get("kid")
        if not kid:
            return _inactive

        # Look up signing key
        signing_key = await signing_key_repo.get_signing_key_by_kid(session, kid)
        if signing_key is None:
            return _inactive

        # Verify signature + expiration + issuer
        try:
            payload = verify_access_token(data.token, signing_key.public_key, config)
        except Exception:
            return _inactive

        # Check user exists and is not banned
        user = await user_repo.get_user_by_id(session, uuid.UUID(payload["sub"]))
        if user is None:
            return _inactive

        if user.banned:
            return _inactive

        # Check token version matches (detects stale tokens after role change/ban)
        if payload.get("ver") != user.token_version:
            return _inactive

        # Get fresh roles from DB
        roles = await role_repo.get_roles(session, user.id)

        return IntrospectResponse(
            active=True,
            sub=payload["sub"],
            email=payload["email"],
            name=payload.get("name"),
            roles=roles,
            token_version=user.token_version,
            exp=payload["exp"],
            iat=payload["iat"],
            iss=payload["iss"],
        )

    return router
