"""FastAPI OAuth router — factory that creates OAuth endpoints for each provider."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import AuthError
from authfort.core.oauth import create_oauth_state, oauth_authenticate, verify_oauth_state
from authfort.core.schemas import AuthResponse
from authfort.events import HookRegistry, get_collector
from authfort.integrations.fastapi.cookies import set_auth_cookies
from authfort.integrations.fastapi.router import _auth_error_detail
from authfort.providers.base import OAuthProvider


def create_oauth_router(
    config: AuthFortConfig,
    get_db: Callable,
    providers: list[OAuthProvider],
    hooks: HookRegistry,
) -> APIRouter:
    """Create a FastAPI router with OAuth authorize/callback endpoints for each provider.

    Registers:
        GET /oauth/{provider_name}/authorize
        GET /oauth/{provider_name}/callback
    """
    router = APIRouter(tags=["oauth"])
    provider_map: dict[str, OAuthProvider] = {p.name: p for p in providers}

    @router.get("/oauth/{provider_name}/authorize")
    async def oauth_authorize(
        provider_name: str,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_db)],
    ):
        """Initiate OAuth flow — redirect to provider's consent screen."""
        provider = provider_map.get(provider_name)
        if provider is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "unknown_provider", "message": f"Provider '{provider_name}' is not configured"},
            )

        oauth_state = await create_oauth_state(session, config=config, provider_name=provider_name)

        redirect_uri = provider.redirect_uri
        if redirect_uri is None:
            redirect_uri = str(request.url_for("oauth_callback", provider_name=provider_name))

        auth_url = provider.get_authorization_url(
            redirect_uri=redirect_uri,
            state=oauth_state.state,
            code_challenge=oauth_state.code_challenge,
        )
        return RedirectResponse(url=auth_url, status_code=302)

    @router.get("/oauth/{provider_name}/callback", response_model=AuthResponse)
    async def oauth_callback(
        provider_name: str,
        request: Request,
        response: Response,
        session: Annotated[AsyncSession, Depends(get_db)],
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ):
        """OAuth callback — exchanges code for tokens and logs user in."""
        if error:
            raise HTTPException(
                status_code=400,
                detail={"error": "oauth_provider_error", "message": error_description or error},
            )

        if not code or not state:
            raise HTTPException(
                status_code=400,
                detail={"error": "oauth_missing_params", "message": "Missing code or state parameter"},
            )

        provider = provider_map.get(provider_name)
        if provider is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "unknown_provider", "message": f"Provider '{provider_name}' is not configured"},
            )

        try:
            code_verifier = await verify_oauth_state(
                session, config=config, state=state, expected_provider=provider_name,
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        redirect_uri = provider.redirect_uri
        if redirect_uri is None:
            redirect_uri = str(request.url_for("oauth_callback", provider_name=provider_name))

        try:
            result = await oauth_authenticate(
                session,
                config=config,
                provider=provider,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)
        return result

    return router
