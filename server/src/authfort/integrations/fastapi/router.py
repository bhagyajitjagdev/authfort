"""FastAPI auth router — factory that creates auth endpoints bound to an AuthFort config."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import AuthError, login, logout, refresh, signup
from authfort.core.schemas import (
    AuthResponse,
    LoginRequest,
    RefreshRequest,
    SignupRequest,
    UserResponse,
)
from authfort.events import HookRegistry, LoginFailed, get_collector
from authfort.integrations.fastapi.cookies import clear_auth_cookies, set_auth_cookies
from authfort.integrations.fastapi.deps import create_current_user_dep


def _auth_error_detail(e: AuthError) -> dict:
    """Build HTTPException detail dict from an AuthError."""
    detail = {"error": e.code, "message": e.message}
    if e.extra:
        detail.update(e.extra)
    return detail


def create_auth_router(
    config: AuthFortConfig, get_db: Callable, hooks: HookRegistry,
) -> APIRouter:
    """Create a FastAPI router with all auth endpoints.

    Args:
        config: The AuthFortConfig instance.
        get_db: An async generator dependency that yields AsyncSession.
        hooks: The HookRegistry for emitting events.
    """
    router = APIRouter(tags=["auth"])
    current_user_dep = create_current_user_dep(config, get_db)

    @router.post("/signup", response_model=AuthResponse, status_code=201)
    async def signup_endpoint(
        data: SignupRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Register a new user with email and password."""
        if not config.allow_signup:
            raise HTTPException(
                status_code=403,
                detail={"error": "signup_disabled", "message": "Registration is currently disabled"},
            )
        try:
            result = await signup(
                session,
                config=config,
                email=data.email,
                password=data.password,
                name=data.name,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/login", response_model=AuthResponse)
    async def login_endpoint(
        data: LoginRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Authenticate with email and password."""
        try:
            result = await login(
                session,
                config=config,
                email=data.email,
                password=data.password,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            # Emit login_failed directly (no DB mutation to wait for)
            await hooks.emit("login_failed", LoginFailed(
                email=data.email,
                reason=e.code,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("User-Agent"),
            ))
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/refresh", response_model=AuthResponse)
    async def refresh_endpoint(
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
        data: RefreshRequest | None = None,
    ):
        """Refresh the access token using a refresh token."""
        raw_refresh_token = None
        if data and data.refresh_token:
            raw_refresh_token = data.refresh_token
        elif config.cookie is not None:
            raw_refresh_token = request.cookies.get(config.cookie.refresh_cookie_name)

        if not raw_refresh_token:
            raise HTTPException(
                status_code=401,
                detail={"error": "refresh_token_missing", "message": "No refresh token provided"},
            )

        try:
            result = await refresh(
                session,
                config=config,
                raw_refresh_token=raw_refresh_token,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            clear_auth_cookies(config, response)
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/logout", status_code=204)
    async def logout_endpoint(
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
        data: RefreshRequest | None = None,
    ):
        """Logout — revoke the refresh token and clear cookies."""
        raw_refresh_token = None
        if data and data.refresh_token:
            raw_refresh_token = data.refresh_token
        elif config.cookie is not None:
            raw_refresh_token = request.cookies.get(config.cookie.refresh_cookie_name)

        if raw_refresh_token:
            await logout(
                session, config=config, raw_refresh_token=raw_refresh_token,
                events=get_collector(),
            )

        clear_auth_cookies(config, response)

    @router.get("/me", response_model=UserResponse)
    async def me_endpoint(
        user: Annotated[UserResponse, Depends(current_user_dep)],
    ):
        """Get the current authenticated user's profile."""
        return user

    return router
