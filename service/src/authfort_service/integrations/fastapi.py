"""FastAPI dependencies for authfort-service."""

from fastapi import Depends, HTTPException, Request

from authfort_service.verifier import JWTVerifier, TokenPayload, TokenVerificationError


def create_current_user_dep(
    verifier: JWTVerifier, *, cookie_name: str | None = None,
):
    """Create a FastAPI dependency that extracts and verifies the JWT.

    Token resolution order:
    1. ``Authorization: Bearer <token>`` header
    2. Cookie named ``cookie_name`` (if configured)
    """

    async def current_user(request: Request) -> TokenPayload:
        token: str | None = None

        # 1. Try Bearer header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

        # 2. Fall back to cookie
        if token is None and cookie_name:
            token = request.cookies.get(cookie_name)

        if not token:
            raise HTTPException(
                status_code=401,
                detail={"error": "token_missing", "message": "No access token provided"},
            )

        try:
            return await verifier.verify(token)
        except TokenVerificationError as e:
            raise HTTPException(
                status_code=401,
                detail={"error": e.code, "message": e.message},
            )

    return current_user


def create_require_role_dep(
    verifier: JWTVerifier, role: str | list[str], *, cookie_name: str | None = None,
):
    """Create a FastAPI dependency that requires a specific role."""
    required_roles = [role] if isinstance(role, str) else role
    current_user_dep = create_current_user_dep(verifier, cookie_name=cookie_name)

    async def check_role(
        user: TokenPayload = Depends(current_user_dep),
    ) -> TokenPayload:
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
