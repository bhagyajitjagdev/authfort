# authfort

Complete authentication and authorization library for Python.

## Install

```bash
pip install authfort[fastapi]
# or with SQLite: pip install authfort[sqlite,fastapi]
```

## Quick Start

```python
from authfort import AuthFort, CookieConfig
from fastapi import FastAPI, Depends

auth = AuthFort(
    database_url="postgresql+asyncpg://user:pass@localhost/mydb",
    cookie=CookieConfig(),
)

app = FastAPI()
app.include_router(auth.fastapi_router(), prefix="/auth")
app.include_router(auth.jwks_router())

@app.get("/profile")
async def profile(user=Depends(auth.current_user)):
    return {"email": user.email, "roles": user.roles}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /auth/signup | Create account |
| POST | /auth/login | Sign in |
| POST | /auth/refresh | Refresh access token |
| POST | /auth/logout | Sign out |
| GET | /auth/me | Get current user |
| GET | /auth/oauth/{provider}/authorize | Start OAuth flow |
| GET | /auth/oauth/{provider}/callback | OAuth callback |
| POST | /auth/introspect | Token introspection |
| GET | /.well-known/jwks.json | Public signing keys |

## Features

- Email/password auth with argon2 hashing
- JWT RS256 with automatic key management
- Refresh token rotation with theft detection
- OAuth 2.1 with PKCE (Google, GitHub)
- Role-based access control
- Session management (list, revoke)
- Ban/unban users
- Event hooks
- JWKS + key rotation
- Cookie and bearer token modes
- Multi-database: PostgreSQL (default), SQLite, MySQL

## OAuth

```python
from authfort import AuthFort, GoogleProvider, GitHubProvider

auth = AuthFort(
    database_url="...",
    providers=[
        GoogleProvider(client_id="...", client_secret="..."),
        GitHubProvider(client_id="...", client_secret="..."),
    ],
)
```

## Programmatic API

```python
# Create users without the HTTP endpoint
result = await auth.create_user("admin@example.com", "password", name="Admin")

# Roles
await auth.add_role(user_id, "admin")
await auth.remove_role(user_id, "editor")

# Sessions
sessions = await auth.get_sessions(user_id, active_only=True)
await auth.revoke_session(session_id)

# Ban/unban
await auth.ban_user(user_id)
await auth.unban_user(user_id)
```

## License

[MIT](../LICENSE)
