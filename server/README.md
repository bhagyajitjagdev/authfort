<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-dark.svg" width="60">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-light.svg" width="60">
  <img alt="AuthFort" src="https://raw.githubusercontent.com/bhagyajitjagdev/authfort/main/.github/logo-light.svg" width="60">
</picture>

# authfort

[![PyPI](https://img.shields.io/pypi/v/authfort)](https://pypi.org/project/authfort/)
[![Coverage](https://codecov.io/gh/bhagyajitjagdev/authfort/branch/main/graph/badge.svg?flag=server)](https://codecov.io/gh/bhagyajitjagdev/authfort)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/Docs-blue?logo=readthedocs&logoColor=white)](https://bhagyajitjagdev.github.io/authfort/server/configuration/)

</div>

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
| POST | /auth/magic-link | Request magic link |
| POST | /auth/magic-link/verify | Verify magic link |
| POST | /auth/otp | Request email OTP |
| POST | /auth/otp/verify | Verify email OTP |
| POST | /auth/verify-email | Verify email address |
| GET | /auth/oauth/{provider}/authorize | Start OAuth flow |
| GET | /auth/oauth/{provider}/callback | OAuth callback |
| POST | /auth/introspect | Token introspection |
| GET | /.well-known/jwks.json | Public signing keys |

## Features

- Email/password auth with argon2 hashing
- JWT RS256 with automatic key management
- Refresh token rotation with theft detection
- OAuth 2.1 with PKCE (Google, GitHub, or any provider via GenericOAuthProvider/GenericOIDCProvider)
- Email verification, magic links, email OTP (passwordless)
- Role-based access control
- Password reset (programmatic — you control delivery)
- Change password (with old password verification)
- Session management (list, revoke, revoke all except current)
- Ban/unban users
- Event hooks (22 event types)
- JWKS + key rotation
- Cookie and bearer token modes
- Multi-database: PostgreSQL (default), SQLite, MySQL via SQLAlchemy

## OAuth

```python
from authfort import AuthFort, GoogleProvider, GitHubProvider, GenericOIDCProvider

auth = AuthFort(
    database_url="...",
    providers=[
        GoogleProvider(client_id="...", client_secret="..."),
        GitHubProvider(client_id="...", client_secret="..."),
        GenericOIDCProvider(
            "keycloak",
            client_id="...",
            client_secret="...",
            discovery_url="https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration",
        ),
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

# Password reset (you handle delivery — email, SMS, etc.)
token = await auth.create_password_reset_token("user@example.com")
if token:
    send_email(email, f"https://myapp.com/reset?token={token}")
await auth.reset_password(token, "new_password")

# Change password (authenticated)
await auth.change_password(user_id, "old_password", "new_password")

# Sessions
sessions = await auth.get_sessions(user_id, active_only=True)
await auth.revoke_session(session_id)
await auth.revoke_all_sessions(user_id, exclude=user.session_id)  # keep current

# Ban/unban
await auth.ban_user(user_id)
await auth.unban_user(user_id)
```

## License

[MIT](../LICENSE)
