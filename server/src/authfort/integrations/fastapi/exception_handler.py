"""FastAPI exception handler for AuthError.

Registered automatically by ``AuthFort.install_fastapi()``. Downstream apps can
also import and register manually:

    from fastapi import FastAPI
    from authfort.integrations.fastapi import authfort_exception_handler
    from authfort.core.errors import AuthError

    app = FastAPI()
    app.add_exception_handler(AuthError, authfort_exception_handler)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request
    from fastapi.responses import JSONResponse

    from authfort.core.errors import AuthError


async def authfort_exception_handler(request: "Request", exc: "AuthError"):
    """Convert AuthError to JSON response matching the router's error shape.

    Produces: ``{"detail": {"error": <code>, "message": <message>, **extra}}``
    with the appropriate HTTP status code.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": {
                "error": exc.code,
                "message": exc.message,
                **exc.extra,
            },
        },
    )
