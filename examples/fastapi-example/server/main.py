"""Example auth server using AuthFort.

This is the central auth server that:
  - Manages users, passwords, OAuth, sessions
  - Issues JWTs signed with RS256
  - Serves public keys at /.well-known/jwks.json (for microservices)
  - Provides token introspection at /auth/introspect (for real-time checks)

Run:  uvicorn main:app --reload --port 8000
"""

import os
import uuid

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from authfort import AuthFort, CookieConfig, GitHubProvider, GoogleProvider
from authfort.core.schemas import UserResponse

auth = AuthFort(
    database_url=os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/authfort",
    ),
    cookie=CookieConfig(secure=False),  # secure=False for localhost dev
    # --- Microservice support ---
    introspect_secret=os.environ.get("INTROSPECT_SECRET"),  # protects /auth/introspect
    key_rotation_ttl=60 * 60 * 48,  # 48h — old keys stay valid after rotation
    # --- Registration control ---
    # allow_signup=False,  # disable /auth/signup endpoint (invite-only mode)
    #                      # use auth.create_user() to create users programmatically
    # --- OAuth providers (uncomment and add your credentials) ---
    #
    # Setup:
    #   1. Google — https://console.cloud.google.com/apis/credentials
    #      - Create OAuth 2.0 Client ID (Web application)
    #      - Add redirect URI: http://localhost:8000/auth/oauth/google/callback
    #
    #   2. GitHub — https://github.com/settings/developers
    #      - Create OAuth App
    #      - Set callback URL: http://localhost:8000/auth/oauth/github/callback
    #
    # providers=[
    #     GoogleProvider(
    #         client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    #         client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    #     ),
    #     GitHubProvider(
    #         client_id=os.environ.get("GITHUB_CLIENT_ID", ""),
    #         client_secret=os.environ.get("GITHUB_CLIENT_SECRET", ""),
    #     ),
    # ],
)

app = FastAPI(title="AuthFort Auth Server")


# ---------------------------------------------------------------------------
# Event hooks — react to auth events (emails, audit logs, analytics, etc.)
# Hooks fire AFTER the DB transaction commits. Errors are logged, never propagate.
# ---------------------------------------------------------------------------


@auth.on("user_created")
async def on_user_created(event):
    """Send a welcome email, sync to CRM, etc."""
    print(f"[hook] New user created: {event.email} (via {event.provider})")


@auth.on("login")
async def on_login(event):
    """Audit log, analytics, etc."""
    print(f"[hook] Login: {event.email} from {event.ip_address}")


@auth.on("login_failed")
async def on_login_failed(event):
    """Rate-limit, alert, etc."""
    print(f"[hook] Login failed: {event.email} — reason: {event.reason}")


@auth.on("user_banned")
async def on_user_banned(event):
    """Notify the user, log for compliance, etc."""
    print(f"[hook] User banned: {event.user_id}")


@auth.on("key_rotated")
async def on_key_rotated(event):
    """Log key rotation for audit trail."""
    print(f"[hook] Key rotated: {event.old_kid} → {event.new_kid}")


# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------

# Auth router — /auth/signup, /auth/login, /auth/refresh, /auth/logout, /auth/me
#               /auth/introspect (token introspection for microservices)
# With OAuth providers enabled, also:
#   /auth/oauth/google/authorize, /auth/oauth/google/callback
#   /auth/oauth/github/authorize, /auth/oauth/github/callback
app.include_router(auth.fastapi_router(), prefix="/auth")

# JWKS endpoint at root — serves /.well-known/jwks.json
# Microservices fetch public keys from this endpoint to verify JWTs locally.
app.include_router(auth.jwks_router())


# ---------------------------------------------------------------------------
# App routes
# ---------------------------------------------------------------------------


@app.get("/")
async def root():
    return {"message": "AuthFort Auth Server", "docs": "/docs"}


@app.get("/profile")
async def profile(user: UserResponse = Depends(auth.current_user)):
    """Protected route — requires a valid access token."""
    return {
        "message": f"Hello, {user.name or user.email}!",
        "user": user.model_dump(mode="json"),
    }


@app.get("/admin")
async def admin_only(user: UserResponse = Depends(auth.require_role("admin"))):
    """Admin-only route — requires the 'admin' role."""
    return {
        "message": "Welcome, admin!",
        "user": user.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------------
# Role management — AuthFort provides add_role/remove_role,
# YOU decide who can call them.
# ---------------------------------------------------------------------------


class RoleRequest(BaseModel):
    user_id: uuid.UUID
    role: str


@app.post("/make-admin")
async def make_admin(user: UserResponse = Depends(auth.current_user)):
    """Make yourself an admin. Demo only — protect or remove in production."""
    await auth.add_role(user.id, "admin")
    return {"message": f"'{user.email}' is now an admin. Re-login to get a fresh token."}


@app.post("/admin/assign-role")
async def assign_role(
    data: RoleRequest,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Assign a role to a user. Only admins can do this."""
    await auth.add_role(data.user_id, data.role)
    return {"message": f"Role '{data.role}' assigned", "user_id": str(data.user_id)}


@app.post("/admin/remove-role")
async def remove_role(
    data: RoleRequest,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Remove a role from a user. Only admins can do this."""
    await auth.remove_role(data.user_id, data.role)
    return {"message": f"Role '{data.role}' removed", "user_id": str(data.user_id)}


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


@app.get("/my-sessions")
async def my_sessions(user: UserResponse = Depends(auth.current_user)):
    """List your own active sessions."""
    sessions = await auth.get_sessions(user.id, active_only=True)
    return [s.model_dump(mode="json") for s in sessions]


@app.delete("/my-sessions/{session_id}")
async def revoke_my_session(
    session_id: uuid.UUID,
    user: UserResponse = Depends(auth.current_user),
):
    """Revoke one of your own sessions (e.g. log out another device)."""
    sessions = await auth.get_sessions(user.id)
    if not any(s.id == session_id for s in sessions):
        return {"error": "Session not found"}
    revoked = await auth.revoke_session(session_id)
    return {"revoked": revoked}


@app.get("/admin/sessions/{user_id}")
async def admin_list_sessions(
    user_id: uuid.UUID,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Admin: list all sessions for any user."""
    sessions = await auth.get_sessions(user_id)
    return [s.model_dump(mode="json") for s in sessions]


@app.delete("/admin/sessions/{user_id}")
async def admin_revoke_all_sessions(
    user_id: uuid.UUID,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Admin: revoke ALL sessions for a user (force logout everywhere)."""
    await auth.revoke_all_sessions(user_id)
    return {"message": f"All sessions revoked for user {user_id}"}


# ---------------------------------------------------------------------------
# User banning
# ---------------------------------------------------------------------------


@app.post("/admin/ban/{user_id}")
async def ban_user(
    user_id: uuid.UUID,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Admin: ban a user — immediately locks them out everywhere."""
    await auth.ban_user(user_id)
    return {"message": f"User {user_id} has been banned"}


@app.post("/admin/unban/{user_id}")
async def unban_user(
    user_id: uuid.UUID,
    admin: UserResponse = Depends(auth.require_role("admin")),
):
    """Admin: unban a user — allows them to login again."""
    await auth.unban_user(user_id)
    return {"message": f"User {user_id} has been unbanned"}


# ---------------------------------------------------------------------------
# Key rotation — call from cron job or admin endpoint
# ---------------------------------------------------------------------------


@app.post("/admin/rotate-key")
async def rotate_key(admin: UserResponse = Depends(auth.require_role("admin"))):
    """Rotate the signing key. Old tokens remain valid for the configured TTL."""
    new_kid = await auth.rotate_key()
    return {"message": "Key rotated", "new_kid": new_kid}


@app.post("/admin/cleanup-keys")
async def cleanup_keys(admin: UserResponse = Depends(auth.require_role("admin"))):
    """Remove expired signing keys that are past their TTL."""
    deleted = await auth.cleanup_expired_keys()
    return {"message": f"Cleaned up {deleted} expired key(s)"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
