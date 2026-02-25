"""FastAPI OAuth router — factory that creates OAuth endpoints for each provider."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from authfort.config import AuthFortConfig
from authfort.core.auth import AuthError
from authfort.core.oauth import create_oauth_state, oauth_authenticate, verify_oauth_state
from authfort.core.schemas import AuthResponse
from authfort.events import HookRegistry, get_collector
from authfort.integrations.fastapi.cookies import set_auth_cookies
from authfort.integrations.fastapi.router import _auth_error_detail, _create_rate_limit_dep
from authfort.providers.base import OAuthProvider


def create_oauth_router(
    config: AuthFortConfig,
    get_db: Callable,
    providers: list[OAuthProvider],
    hooks: HookRegistry,
    *,
    rate_limit_store=None,
) -> APIRouter:
    """Create a FastAPI router with OAuth authorize/callback endpoints for each provider.

    Registers:
        GET /oauth/{provider_name}/authorize
        GET /oauth/{provider_name}/callback
    """
    router = APIRouter(tags=["oauth"])
    provider_map: dict[str, OAuthProvider] = {p.name: p for p in providers}

    rl = config.rate_limit
    _authorize_rl = []
    if rl is not None and rl.oauth_authorize and rate_limit_store is not None:
        _authorize_rl = [Depends(_create_rate_limit_dep(
            hooks, rate_limit_store, "oauth_authorize", rl.oauth_authorize,
        ))]

    @router.get("/oauth/{provider_name}/authorize", dependencies=_authorize_rl)
    async def oauth_authorize(
        provider_name: str,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_db)],
        redirect_to: str | None = None,
        mode: str | None = None,
    ):
        """Initiate OAuth flow — redirect to provider's consent screen."""
        provider = provider_map.get(provider_name)
        if provider is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "unknown_provider", "message": f"Provider '{provider_name}' is not configured"},
            )

        # Validate redirect_to — must be a relative path to prevent open redirect
        if redirect_to and not redirect_to.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_redirect", "message": "redirect_to must be a relative path"},
            )

        oauth_state = await create_oauth_state(
            session, config=config, provider_name=provider_name,
            redirect_to=redirect_to, mode=mode,
        )

        redirect_uri = provider.redirect_uri
        if redirect_uri is None:
            redirect_uri = str(request.url_for("oauth_callback", provider_name=provider_name))

        # Pre-fetch OIDC discovery if needed (GenericOIDCProvider)
        if hasattr(provider, '_ensure_discovered'):
            await provider._ensure_discovered()

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

        def _fire_login_failed(reason: str) -> None:
            """Fire a login_failed event on the request-scoped collector (if available)."""
            collector = get_collector()
            if collector is not None:
                from authfort.events import LoginFailed

                collector.collect("login_failed", LoginFailed(
                    email=None,
                    reason=reason,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("User-Agent"),
                ))

        if error:
            _fire_login_failed("oauth_provider_error")
            raise HTTPException(
                status_code=400,
                detail={"error": "oauth_provider_error", "message": error_description or error},
            )

        if not code or not state:
            _fire_login_failed("oauth_missing_params")
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
            state_data = await verify_oauth_state(
                session, config=config, state=state, expected_provider=provider_name,
            )
        except AuthError as e:
            _fire_login_failed("oauth_state_invalid")
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
                code_verifier=state_data.code_verifier,
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host if request.client else None,
                events=get_collector(),
            )
        except AuthError as e:
            _fire_login_failed(e.code)
            raise HTTPException(status_code=e.status_code, detail=_auth_error_detail(e))

        set_auth_cookies(config, response, result)

        # Popup mode: return HTML that posts tokens to opener and closes
        if state_data.mode == "popup":
            import json

            result_json = json.dumps(result.model_dump(), default=str)
            html = (
                "<!DOCTYPE html><html><body><script>"
                f"window.opener.postMessage({result_json},'*');"
                "window.close();"
                "</script></body></html>"
            )
            return HTMLResponse(content=html)

        # Redirect mode: redirect to specified URL after setting cookies
        if state_data.redirect_to:
            redirect_url = state_data.redirect_to
            if config.frontend_url:
                redirect_url = config.frontend_url + redirect_url
            return RedirectResponse(url=redirect_url, status_code=302)

        return result

    return router
