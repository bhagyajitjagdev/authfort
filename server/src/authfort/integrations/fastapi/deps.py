"""FastAPI dependencies — factory functions that produce dependencies bound to an AuthFort config."""

import uuid
from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.schemas import UserResponse
from authfort.core.tokens import get_unverified_header, verify_access_token
from authfort.repositories import role as role_repo
from authfort.repositories import signing_key as signing_key_repo
from authfort.repositories import user as user_repo


def create_current_user_dep(config: AuthFortConfig, get_db: Callable):
    """Factory: create a FastAPI dependency that extracts and verifies the current user."""

    async def _extract_token(request: Request) -> str:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]

        if config.cookie is not None:
            token = request.cookies.get(config.cookie.access_cookie_name)
            if token:
                return token

        raise HTTPException(
            status_code=401,
            detail={"error": "token_missing", "message": "No access token provided"},
        )

    async def current_user(
        request: Request,
        session: AsyncSession = Depends(get_db),
    ) -> UserResponse:
        token = await _extract_token(request)

        try:
            header = get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail={"error": "token_invalid", "message": "Malformed token"})

        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail={"error": "token_invalid", "message": "Token missing kid header"})

        signing_key = await signing_key_repo.get_signing_key_by_kid(session, kid)
        if signing_key is None:
            raise HTTPException(status_code=401, detail={"error": "token_invalid", "message": "Unknown signing key"})

        try:
            payload = verify_access_token(token, signing_key.public_key, config)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail={"error": "token_expired", "message": "Access token has expired"})
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail={"error": "token_invalid", "message": "Invalid access token"})

        user = await user_repo.get_user_by_id(session, uuid.UUID(payload["sub"]))
        if user is None:
            raise HTTPException(status_code=401, detail={"error": "user_not_found", "message": "User no longer exists"})

        if user.banned:
            raise HTTPException(status_code=403, detail={"error": "user_banned", "message": "This account has been banned"})

        if payload.get("ver") != user.token_version:
            raise HTTPException(status_code=401, detail={"error": "token_version_mismatch", "message": "Token has been invalidated"})

        roles = await role_repo.get_roles(session, user.id)

        session_id = None
        if payload.get("sid"):
            session_id = uuid.UUID(payload["sid"])

        return UserResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            email_verified=user.email_verified,
            avatar_url=user.avatar_url,
            phone=user.phone,
            roles=roles,
            created_at=user.created_at,
            session_id=session_id,
        )

    return current_user


def create_require_role_dep(config: AuthFortConfig, get_db: Callable, role: str | list[str]):
    """Factory: create a FastAPI dependency that requires a specific role."""
    required_roles = [role] if isinstance(role, str) else role
    current_user_dep = create_current_user_dep(config, get_db)

    async def check_role(
        user: UserResponse = Depends(current_user_dep),
    ) -> UserResponse:
        if not any(r in user.roles for r in required_roles):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_role",
                    "message": f"Requires one of: {', '.join(required_roles)}",
                },
            )
        return user

    return check_role
