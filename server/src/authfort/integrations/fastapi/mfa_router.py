"""FastAPI MFA router — TOTP setup, verification, and management endpoints."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import (
    admin_disable_mfa,
    complete_mfa_login,
    disable_mfa,
    enable_mfa_confirm,
    enable_mfa_init,
    get_mfa_status,
    regenerate_backup_codes,
)
from authfort.core.errors import AuthError
from authfort.core.schemas import (
    AuthResponse,
    MFAConfirmRequest,
    MFADisableRequest,
    MFARegenerateBackupCodesRequest,
    MFASetup,
    MFAStatus,
    MFAVerifyRequest,
)
from authfort.events import HookRegistry, get_collector
from authfort.integrations.fastapi.cookies import set_auth_cookies
from authfort.integrations.fastapi.deps import create_current_user_dep
from authfort.integrations.fastapi.proxy import get_client_ip


def _auth_error_detail(e: AuthError) -> dict:
    detail = {"error": e.code, "message": e.message}
    if e.extra:
        detail.update(e.extra)
    return detail


def _create_rate_limit_dep(
    config: AuthFortConfig,
    hooks: HookRegistry,
    store,
    endpoint_name: str,
    limit_str: str,
):
    """Create a FastAPI dependency that enforces IP-based rate limiting."""
    from authfort.ratelimit import parse_rate_limit

    limit = parse_rate_limit(limit_str)

    async def check_rate_limit(request: Request):
        from authfort.events import RateLimitExceeded

        ip = get_client_ip(request, config) or "unknown"
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


def create_mfa_router(
    config: AuthFortConfig,
    get_db: Callable,
    hooks: HookRegistry,
    *,
    rate_limit_store=None,
) -> APIRouter:
    """Create a FastAPI router with all MFA endpoints.

    Args:
        config: The AuthFortConfig instance.
        get_db: An async generator dependency that yields AsyncSession.
        hooks: The HookRegistry for emitting events.
    """
    router = APIRouter(prefix="/mfa", tags=["mfa"])
    current_user_dep = create_current_user_dep(config, get_db)

    # Rate limit for the /mfa/verify endpoint
    rl = config.rate_limit
    _mfa_verify_rl = []
    if rl is not None and rate_limit_store is not None and rl.mfa_verify:
        _mfa_verify_rl = [
            Depends(_create_rate_limit_dep(config, hooks, rate_limit_store, "mfa_verify", rl.mfa_verify))
        ]

    @router.post("/verify", response_model=AuthResponse, dependencies=_mfa_verify_rl)
    async def mfa_verify_endpoint(
        data: MFAVerifyRequest,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Complete a login that requires MFA.

        Submit the ``mfa_token`` from the login response alongside a 6-digit
        TOTP code (or a backup code) to receive full auth tokens.
        """
        try:
            result = await complete_mfa_login(
                session,
                config=config,
                mfa_token=data.mfa_token,
                code=data.code,
                user_agent=request.headers.get("User-Agent"),
                ip_address=get_client_ip(request, config),
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    @router.post("/init", response_model=MFASetup)
    async def mfa_init_endpoint(
        session: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(current_user_dep),
    ):
        """Start TOTP MFA setup.

        Returns a ``secret`` and a ``qr_uri`` (otpauth:// URI). Encode the URI
        into a QR image on the client and show it to the user to scan.

        MFA is NOT enabled yet — call ``/auth/mfa/confirm`` with a valid code
        to activate it.
        """
        try:
            result = await enable_mfa_init(
                session, config=config, user_id=current_user.id,
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))
        return result

    @router.post("/confirm", response_model=list[str])
    async def mfa_confirm_endpoint(
        data: MFAConfirmRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(current_user_dep),
    ):
        """Confirm TOTP setup and enable MFA.

        Verifies the first TOTP code from the authenticator app, enables MFA,
        and returns plaintext backup codes. **Show these to the user exactly once
        and instruct them to save them.** They cannot be retrieved again.
        """
        try:
            backup_codes = await enable_mfa_confirm(
                session,
                config=config,
                user_id=current_user.id,
                code=data.code,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))
        return backup_codes

    @router.post("/disable", status_code=204)
    async def mfa_disable_endpoint(
        data: MFADisableRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(current_user_dep),
    ):
        """Disable TOTP MFA for the current user.

        Requires a valid TOTP code or an unused backup code for confirmation.
        """
        try:
            await disable_mfa(
                session,
                config=config,
                user_id=current_user.id,
                code=data.code,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

    @router.post("/backup-codes/regenerate", response_model=list[str])
    async def mfa_regenerate_backup_codes_endpoint(
        data: MFARegenerateBackupCodesRequest,
        session: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(current_user_dep),
    ):
        """Regenerate backup codes.

        Requires a valid TOTP code. Invalidates all existing backup codes and
        returns a new set. **Show these to the user exactly once.**
        """
        try:
            backup_codes = await regenerate_backup_codes(
                session,
                config=config,
                user_id=current_user.id,
                totp_code=data.code,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))
        return backup_codes

    @router.get("/status", response_model=MFAStatus)
    async def mfa_status_endpoint(
        session: Annotated[AsyncSession, Depends(get_db)],
        current_user=Depends(current_user_dep),
    ):
        """Get the current MFA status for the authenticated user."""
        try:
            return await get_mfa_status(session, user_id=current_user.id)
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

    return router
