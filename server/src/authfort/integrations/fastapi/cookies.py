"""Shared cookie helpers for FastAPI auth endpoints."""

from __future__ import annotations

from fastapi import Response

from authfort.config import AuthFortConfig
from authfort.core.schemas import AuthResponse


def set_auth_cookies(config: AuthFortConfig, response: Response, auth_response: AuthResponse) -> None:
    """Set auth cookies on the response if cookie mode is enabled."""
    if config.cookie is None:
        return
    c = config.cookie
    response.set_cookie(
        key=c.access_cookie_name,
        value=auth_response.tokens.access_token,
        max_age=config.access_token_expire_seconds,
        secure=c.secure,
        httponly=c.httponly,
        samesite=c.samesite,
        path=c.path,
        domain=c.domain,
    )
    response.set_cookie(
        key=c.refresh_cookie_name,
        value=auth_response.tokens.refresh_token,
        max_age=config.refresh_token_expire_seconds,
        secure=c.secure,
        httponly=c.httponly,
        samesite=c.samesite,
        path=c.path,
        domain=c.domain,
    )


def clear_auth_cookies(config: AuthFortConfig, response: Response) -> None:
    """Clear auth cookies on the response if cookie mode is enabled."""
    if config.cookie is None:
        return
    c = config.cookie
    response.delete_cookie(key=c.access_cookie_name, path=c.path, domain=c.domain)
    response.delete_cookie(key=c.refresh_cookie_name, path=c.path, domain=c.domain)
