<div align="center">

# AuthFort

Complete authentication and authorization system for Python applications.
Drop-in auth for FastAPI — JWT, OAuth, roles, sessions, and a TypeScript client SDK.

[![PyPI](https://img.shields.io/pypi/v/authfort?label=authfort&color=blue)](https://pypi.org/project/authfort/)
[![PyPI](https://img.shields.io/pypi/v/authfort-service?label=authfort-service&color=blue)](https://pypi.org/project/authfort-service/)
[![npm](https://img.shields.io/npm/v/authfort-client?label=authfort-client&color=green)](https://www.npmjs.com/package/authfort-client)
[![CI](https://github.com/bhagyajitjagdev/authfort/actions/workflows/ci.yml/badge.svg)](https://github.com/bhagyajitjagdev/authfort/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

</div>

---

## Packages

This is a monorepo with three packages that work together:

| Package | Language | Install | Description |
|---------|----------|---------|-------------|
| **[authfort](server/)** | Python | `pip install authfort` | Full auth server — user management, JWT, OAuth, roles, sessions, JWKS |
| **[authfort-service](service/)** | Python | `pip install authfort-service` | Lightweight JWT verifier for microservices — JWKS + introspection |
| **[authfort-client](client/)** | TypeScript | `npm install authfort-client` | Client SDK — token lifecycle, refresh dedup, React/Vue/Svelte hooks |

## Features

- **Email/Password Auth** — Signup, login, argon2 password hashing, email format validation
- **JWT RS256** — Stateless access tokens with automatic key management
- **Refresh Token Rotation** — Secure rotation with theft detection
- **OAuth 2.1 + PKCE** — Google and GitHub providers, auto account linking
- **Role-Based Access Control** — Add/remove roles, `require_role` dependency
- **Password Reset** — Programmatic token generation (you control delivery — email, SMS, etc.)
- **Change Password** — Old password verification, automatic token invalidation
- **Session Management** — List, revoke individual, revoke all (with `exclude` for "sign out other devices")
- **Ban/Unban** — Instant invalidation (bumps token version, revokes all tokens)
- **Event Hooks** — 15 event types (user_created, login, password_reset, role_added, etc.)
- **JWKS Endpoint** — `/.well-known/jwks.json` with automatic key rotation
- **Token Introspection** — RFC 7662 for microservice architectures
- **Multi-Database** — PostgreSQL (primary), SQLite, MySQL via SQLAlchemy
- **Cookie & Bearer Modes** — HttpOnly cookies or Authorization header
- **Client SDK** — TypeScript with React, Vue, and Svelte integrations
- **Microservice Verifier** — Lightweight JWT verification without database access

## Quick Start

### Auth Server (FastAPI)

```bash
pip install authfort[fastapi]
```

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

@app.get("/api/profile")
async def profile(user=Depends(auth.current_user)):
    return {"email": user.email, "roles": user.roles}
```

This gives you these endpoints out of the box:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/signup` | Create a new user |
| POST | `/auth/login` | Authenticate and get tokens |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Revoke refresh token |
| GET | `/auth/me` | Get current user info |
| GET | `/auth/oauth/{provider}/authorize` | Start OAuth flow |
| GET | `/auth/oauth/{provider}/callback` | OAuth callback |
| GET | `/.well-known/jwks.json` | Public keys (JWKS) |
| POST | `/introspect` | Token introspection (RFC 7662) |

### Programmatic API

For operations beyond the REST endpoints:

```python
# User management
user = await auth.create_user("admin@example.com", "password", name="Admin")
await auth.add_role(user.id, "admin")
await auth.ban_user(user.id)

# Password reset (you handle delivery)
token = await auth.create_password_reset_token("user@example.com")
if token:
    await send_reset_email(email, token)
await auth.reset_password(token, "new_password")

# Change password (authenticated)
await auth.change_password(user.id, "old_password", "new_password")

# Session management
sessions = await auth.get_sessions(user.id, active_only=True)
await auth.revoke_session(session_id)
await auth.revoke_all_sessions(user.id, exclude=user.session_id)  # keep current

# Event hooks
@auth.on("user_created")
async def on_signup(event):
    await send_welcome_email(event.email)

@auth.on("password_reset")
async def on_reset(event):
    log.info(f"Password reset for user {event.user_id}")
```

### Microservice Verifier

For downstream services that need to verify JWTs without database access:

```bash
pip install authfort-service[fastapi]
```

```python
from authfort_service import ServiceAuth

service = ServiceAuth(
    jwks_url="https://auth.example.com/.well-known/jwks.json",
    issuer="authfort",
)

@app.get("/api/data")
async def protected(user=Depends(service.current_user)):
    return {"user": user.sub, "roles": user.roles}
```

### Client SDK

```bash
npm install authfort-client
```

```typescript
import { createAuthClient } from 'authfort-client';

const auth = createAuthClient({
  baseUrl: '/auth',
  tokenMode: 'cookie',
});

await auth.initialize();
await auth.signUp({ email: 'user@example.com', password: 'secret' });
await auth.signIn({ email: 'user@example.com', password: 'secret' });

// auth.fetch() is a drop-in replacement for fetch — handles auth automatically
const res = await auth.fetch('/api/profile');
```

#### React

```tsx
import { AuthProvider, useAuth } from 'authfort-client/react';

function App() {
  return (
    <AuthProvider client={auth}>
      <Profile />
    </AuthProvider>
  );
}

function Profile() {
  const { user, isAuthenticated, isLoading, client } = useAuth();

  if (isLoading) return <p>Loading...</p>;
  if (!isAuthenticated) return <p>Not signed in</p>;

  return <p>Hello {user.email}</p>;
}
```

<details>
<summary><b>Vue</b></summary>

```typescript
import { provideAuth, useAuth } from 'authfort-client/vue';

// Root component
setup() {
  provideAuth(auth);
}

// Any child component
const { user, isAuthenticated } = useAuth();
```

</details>

<details>
<summary><b>Svelte</b></summary>

```typescript
import { createAuthStore } from 'authfort-client/svelte';

const { state, user, isAuthenticated } = createAuthStore(auth);

// In template
{#if $isAuthenticated}
  Hello {$user.email}
{/if}
```

</details>

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Frontend    │     │  Auth Server │     │  Microservices   │
│  (React/Vue) │────▶│  (authfort)  │     │  (authfort-      │
│  authfort-   │     │              │◀────│   service)       │
│  client      │     │  PostgreSQL  │     │                  │
└──────────────┘     │  / SQLite    │     │  Verifies JWTs   │
                     │  / MySQL     │     │  via JWKS        │
                     └──────────────┘     └──────────────────┘
                            │
                            ├── /.well-known/jwks.json
                            ├── /auth/signup, /auth/login, ...
                            └── /introspect
```

## Database Support

| Database | Install | Status |
|----------|---------|--------|
| PostgreSQL | `pip install authfort` (asyncpg included) | Primary, recommended |
| SQLite | `pip install authfort[sqlite]` | Full support |
| MySQL | `pip install authfort[mysql]` | Full support |

## Requirements

- **Python**: 3.11+
- **Node.js**: 18+ (for client SDK)
- **Database**: PostgreSQL, SQLite, or MySQL
- **ORM**: SQLModel (included)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

### Quick Overview

1. Fork the repository
2. Create a feature branch (`feat/my-feature`)
3. Run tests (`uv run pytest tests/ -v` in server/ or service/)
4. Submit a pull request

### Reporting Issues

- **Bug reports** — [Open an issue](https://github.com/bhagyajitjagdev/authfort/issues/new?template=bug_report.md)
- **Feature requests** — [Open an issue](https://github.com/bhagyajitjagdev/authfort/issues/new?template=feature_request.md)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

### Latest — v0.0.4

- Password reset (`create_password_reset_token` + `reset_password`)
- Change password with old password verification
- `revoke_all_sessions` with `exclude` param (sign out other devices)
- `session_id` on `UserResponse` (embedded in JWT as `sid` claim)
- 3 new events: `password_reset_requested`, `password_reset`, `password_changed`

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**If you found this useful, give it a** :star:

[Report Bug](https://github.com/bhagyajitjagdev/authfort/issues/new?template=bug_report.md) · [Request Feature](https://github.com/bhagyajitjagdev/authfort/issues/new?template=feature_request.md) · [Contributing Guide](CONTRIBUTING.md)

Made by [Bhagyajit Jagdev](https://github.com/bhagyajitjagdev)

</div>
