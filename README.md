# AuthFort

Complete authentication and authorization system for Python applications.

## Packages

| Package | Description | Path |
|---------|-------------|------|
| [authfort](server/) | Full auth server — signup, login, JWT RS256, OAuth, roles, sessions, JWKS | `server/` |
| [authfort-service](service/) | Lightweight JWT verifier for microservices — JWKS + introspection | `service/` |
| [authfort-client](client/) | TypeScript client SDK — token lifecycle, refresh, React/Vue/Svelte hooks | `client/` |

## Features

- Email/password authentication with argon2 hashing
- JWT access tokens (RS256) with refresh token rotation
- OAuth 2.1 with PKCE (Google, GitHub)
- Role-based access control
- Session management (list, revoke, revoke all)
- Ban/unban users
- Event hooks (user_created, login, logout, etc.)
- JWKS endpoint + key rotation for microservice architectures
- Token introspection endpoint
- Multi-database support (PostgreSQL, SQLite, MySQL)
- Cookie and bearer token modes
- TypeScript client SDK with framework integrations (React, Vue, Svelte)

## Quick Start

### Server

```python
from authfort import AuthFort, CookieConfig
from fastapi import FastAPI

auth = AuthFort(
    database_url="postgresql+asyncpg://user:pass@localhost/mydb",
    cookie=CookieConfig(),
)

app = FastAPI()
app.include_router(auth.fastapi_router(), prefix="/auth")
app.include_router(auth.jwks_router())
```

### Client

```typescript
import { createAuthClient } from 'authfort-client';

const auth = createAuthClient({ baseUrl: '/auth' });
await auth.initialize();
await auth.signUp({ email: 'user@example.com', password: 'secret' });
```

## License

[MIT](LICENSE)
