"""FastAPI auth router — factory that creates auth endpoints bound to an AuthFort config."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import (
    AuthError,
    create_email_otp,
    create_magic_link_token,
    login,
    logout,
    refresh,
    signup,
    verify_email,
    verify_email_otp,
    verify_magic_link,
)
from authfort.core.schemas import (
    AuthResponse,
    EmailVerifyRequest,
    LoginRequest,
    MagicLinkRequest,
    MagicLinkVerifyRequest,
    OTPRequest,
    OTPVerifyRequest,
    RefreshRequest,
    SignupRequest,
    UserResponse,
)
from authfort.events import HookRegistry, LoginFailed, RateLimitExceeded, get_collector
from authfort.integrations.fastapi.cookies import clear_auth_cookies, set_auth_cookies
from authfort.integrations.fastapi.deps import create_current_user_dep


def _auth_error_detail(e: AuthError) -> dict:
    """Build HTTPException detail dict from an AuthError."""
    detail = {"error": e.code, "message": e.message}
    if e.extra:
        detail.update(e.extra)
    return detail


def _create_rate_limit_dep(
    hooks: HookRegistry,
    store,
    endpoint_name: str,
    limit_str: str,
):
    """Create a FastAPI dependency that enforces IP-based rate limiting."""
    from authfort.ratelimit import parse_rate_limit

    limit = parse_rate_limit(limit_str)

    async def check_rate_limit(request: Request):
        ip = request.client.host if request.client else "unknown"
        ip_key = f"ip:{ip}:{endpoint_name}"
        allowed, remaining, retry_after = store.hit(ip_key, limit)

        if not allowed:
            await hooks.emit(
                "rate_limit_exceeded",
                RateLimitExceeded(
                    endpoint=endpoint_name,
                    ip_address=ip,
                    limit=limit_str,
                    key_type="ip",
                ),
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    return check_rate_limit


async def _check_email_rate_limit(
    hooks: HookRegistry,
    store,
    endpoint_name: str,
    limit_str: str,
    email: str,
    ip: str | None,
) -> None:
    """Check email-based rate limit. Called inline after body parsing."""
    from authfort.ratelimit import parse_rate_limit

    limit = parse_rate_limit(limit_str)
    email_key = f"email:{email.strip().lower()}:{endpoint_name}"
    allowed, remaining, retry_after = store.hit(email_key, limit)

    if not allowed:
        await hooks.emit(
            "rate_limit_exceeded",
            RateLimitExceeded(
                endpoint=endpoint_name,
                ip_address=ip,
                email=email,
                limit=limit_str,
                key_type="email",
            ),
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Please try again later.",
            },
            headers={"Retry-After": str(int(retry_after) + 1)},
        )


def create_auth_router(
    config: AuthFortConfig, get_db: Callable, hooks: HookRegistry,
    *, rate_limit_store=None,
) -> APIRouter:
    """Create a FastAPI router with all auth endpoints.

    Args:
        config: The AuthFortConfig instance.
        get_db: An async generator dependency that yields AsyncSession.
        hooks: The HookRegistry for emitting events.
    """
    router = APIRouter(tags=["auth"])
    current_user_dep = create_current_user_dep(config, get_db)

    # Build per-endpoint rate limit dependencies
    rl = config.rate_limit
    _signup_rl = []
    _login_rl = []
    _refresh_rl = []
    _magic_link_rl = []
    _otp_rl = []
    _verify_email_rl = []

    if rl is not None and rate_limit_store is not None:
        if rl.signup:
            _signup_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "signup", rl.signup))]
        if rl.login:
            _login_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "login", rl.login))]
        if rl.refresh:
            _refresh_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "refresh", rl.refresh))]
        if rl.magic_link:
            _magic_link_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "magic_link", rl.magic_link))]
        if rl.otp:
            _otp_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "otp", rl.otp))]
        if rl.verify_email:
            _verify_email_rl = [Depends(_create_rate_limit_dep(hooks, rate_limit_store, "verify_email", rl.verify_email))]

    @router.post("/signup", response_model=AuthResponse, status_code=201, dependencies=_signup_rl)
    async def signup_endpoint(
        data: SignupRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Register a new user with email and password."""
        if rl is not None and rl.signup and rate_limit_store is not None:
            await _check_email_rate_limit(
                hooks, rate_limit_store, "signup", rl.signup,
                data.email, request.client.host if request.client else None,
            )
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
                avatar_url=data.avatar_url,
                phone=data.phone,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/login", response_model=AuthResponse, dependencies=_login_rl)
    async def login_endpoint(
        data: LoginRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Authenticate with email and password."""
        if rl is not None and rl.login and rate_limit_store is not None:
            await _check_email_rate_limit(
                hooks, rate_limit_store, "login", rl.login,
                data.email, request.client.host if request.client else None,
            )
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

    @router.post("/refresh", response_model=AuthResponse, dependencies=_refresh_rl)
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

    # ------ Passwordless endpoints ------

    @router.post("/magic-link", dependencies=_magic_link_rl)
    async def magic_link_endpoint(
        data: MagicLinkRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Request a magic link for passwordless login."""
        if rl is not None and rl.magic_link and rate_limit_store is not None:
            await _check_email_rate_limit(
                hooks, rate_limit_store, "magic_link", rl.magic_link,
                data.email, None,
            )
        await create_magic_link_token(
            session, config=config, email=data.email, events=get_collector(),
        )
        return {"message": "If an account exists, a magic link has been sent."}

    @router.post("/magic-link/verify", response_model=AuthResponse)
    async def magic_link_verify_endpoint(
        data: MagicLinkVerifyRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Verify a magic link token and log in."""
        try:
            result = await verify_magic_link(
                session,
                config=config,
                token=data.token,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/otp", dependencies=_otp_rl)
    async def otp_endpoint(
        data: OTPRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Request an email OTP code for passwordless login."""
        if rl is not None and rl.otp and rate_limit_store is not None:
            await _check_email_rate_limit(
                hooks, rate_limit_store, "otp", rl.otp,
                data.email, None,
            )
        await create_email_otp(
            session, config=config, email=data.email, events=get_collector(),
        )
        return {"message": "If an account exists, a verification code has been sent."}

    @router.post("/otp/verify", response_model=AuthResponse, dependencies=_otp_rl)
    async def otp_verify_endpoint(
        data: OTPVerifyRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Verify an email OTP code and log in."""
        if rl is not None and rl.otp and rate_limit_store is not None:
            await _check_email_rate_limit(
                hooks, rate_limit_store, "otp", rl.otp,
                data.email, request.client.host if request.client else None,
            )
        try:
            result = await verify_email_otp(
                session,
                config=config,
                email=data.email,
                code=data.code,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/verify-email", dependencies=_verify_email_rl)
    async def verify_email_endpoint(
        data: EmailVerifyRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Verify email address with a verification token."""
        try:
            await verify_email(
                session, token=data.token, events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        return {"message": "Email verified successfully."}

    return router
