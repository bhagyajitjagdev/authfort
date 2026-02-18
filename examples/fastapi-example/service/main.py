"""Example microservice using authfort-service for JWT verification.

This is a downstream microservice that:
  - Has NO database, NO user management, NO token issuance
  - Verifies JWTs locally using the auth server's public keys (JWKS)
  - Optionally introspects tokens for real-time checks (banned, revoked)

The auth server (../server/) issues tokens. This service just verifies them.

Run:  uvicorn main:app --reload --port 8001
"""

import os

from fastapi import Depends, FastAPI, HTTPException, Request

from authfort_service import ServiceAuth, TokenPayload

# ---------------------------------------------------------------------------
# Setup — point at the auth server's JWKS + introspection endpoints
# ---------------------------------------------------------------------------

service_auth = ServiceAuth(
    jwks_url=os.environ.get(
        "JWKS_URL", "http://localhost:8000/.well-known/jwks.json"
    ),
    issuer="authfort",
    # Optional: introspection for real-time checks (banned users, revoked tokens)
    introspect_url=os.environ.get(
        "INTROSPECT_URL", "http://localhost:8000/auth/introspect"
    ),
    introspect_secret=os.environ.get("INTROSPECT_SECRET"),
)

app = FastAPI(title="AuthFort Microservice Example")


# ---------------------------------------------------------------------------
# Protected routes — JWT verified locally via JWKS (fast, no network call)
#
# After the initial JWKS fetch, verification is purely local — no round-trip
# to the auth server. Keys are cached and auto-refreshed on rotation.
# ---------------------------------------------------------------------------


@app.get("/data")
async def get_data(user: TokenPayload = Depends(service_auth.current_user)):
    """Any authenticated user can access this."""
    return {
        "message": f"Hello {user.email}, here's your data",
        "user_id": user.sub,
        "roles": user.roles,
    }


@app.get("/admin/reports")
async def admin_reports(
    user: TokenPayload = Depends(service_auth.require_role("admin")),
):
    """Admin-only route — checks the 'admin' role from the JWT."""
    return {"message": "Admin reports", "requested_by": user.email}


# ---------------------------------------------------------------------------
# Sensitive operations — use introspection for real-time DB checks
#
# JWKS verification is fast but can't detect:
#   - Users banned AFTER the token was issued
#   - Token version bumps (e.g. role changes with immediate=True)
#
# Introspection calls the auth server, which checks the DB in real-time.
# Use it for high-stakes operations where stale tokens are unacceptable.
# ---------------------------------------------------------------------------


@app.post("/transfer")
async def transfer_funds(request: Request):
    """Sensitive operation — introspect the token for real-time validity."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")

    token = auth_header[7:]
    result = await service_auth.introspect(token)

    if not result.active:
        raise HTTPException(status_code=401, detail="Token no longer valid")

    return {
        "message": "Transfer initiated",
        "user": result.email,
        "roles": result.roles,
    }


# ---------------------------------------------------------------------------
# Programmatic usage — verify tokens outside of FastAPI dependencies
# ---------------------------------------------------------------------------


@app.post("/webhook")
async def webhook(request: Request):
    """Example: verify a token passed in a webhook payload."""
    body = await request.json()
    token = body.get("auth_token")
    if not token:
        raise HTTPException(status_code=400, detail="Missing auth_token")

    try:
        payload = await service_auth.verify_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"processed_for": payload.email, "roles": payload.roles}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "example-microservice"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
