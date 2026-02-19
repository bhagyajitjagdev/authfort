# Contributing to AuthFort

Thank you for your interest in contributing to AuthFort!

## Quick Start

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create** a feature branch
4. **Make** your changes
5. **Run tests** to verify
6. **Submit** a pull request

## Project Structure

AuthFort is a monorepo with three packages:

```
authfort/
├── server/          # authfort (Python) — full auth server
│   ├── src/authfort/
│   └── tests/
├── service/         # authfort-service (Python) — JWT verifier
│   ├── src/authfort_service/
│   └── tests/
├── client/          # authfort-client (TypeScript) — client SDK
│   ├── src/
│   └── tests/
└── examples/        # Example applications
```

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- npm (Node package manager)

### Server (`authfort`)

```bash
cd server
uv sync --extra sqlite --extra fastapi
```

### Service (`authfort-service`)

```bash
cd service
uv sync --extra fastapi
```

### Client (`authfort-client`)

```bash
cd client
npm install
```

## Running Tests

### Server Tests

```bash
cd server

# Run with SQLite (no database setup needed)
DATABASE_URL="sqlite+aiosqlite:///test.db" uv run pytest tests/ -v

# Run with PostgreSQL
DATABASE_URL="postgresql+asyncpg://user:pass@localhost/authfort_test" uv run pytest tests/ -v
```

### Service Tests

```bash
cd service
uv run pytest tests/ -v
```

### Client Tests

```bash
cd client
npm test
```

## Ways to Contribute

### Bug Reports

- Use [GitHub Issues](https://github.com/bhagyajitjagdev/authfort/issues)
- Search existing issues before creating a new one
- Include your Python/Node version, database type, and steps to reproduce
- Include the full error traceback if applicable

### Feature Requests

- Open an issue with the `enhancement` label
- Describe the use case and expected behavior
- Consider whether it fits the library's philosophy (functions over routes, no opinions on delivery)

### Adding an OAuth Provider

New OAuth providers follow this pattern:

1. Create `server/src/authfort/providers/your_provider.py`:

```python
from authfort.providers.base import OAuthProvider

class YourProvider(OAuthProvider):
    name = "your_provider"
    authorization_url = "https://provider.com/oauth/authorize"
    token_url = "https://provider.com/oauth/token"
    userinfo_url = "https://provider.com/api/userinfo"
    default_scopes = ["openid", "email", "profile"]

    async def get_user_info(self, access_token: str) -> dict:
        # Fetch and normalize user info
        # Must return: {"email": ..., "name": ..., "provider_user_id": ...}
        ...
```

2. Export it from `server/src/authfort/__init__.py`
3. Add tests in `server/tests/test_oauth.py`

### Adding a Framework Integration

Currently supported: FastAPI. To add Django, Flask, etc.:

1. Create `server/src/authfort/integrations/your_framework/`
2. Implement router/middleware that calls the core functions
3. The core (`core/auth.py`, `core/sessions.py`, etc.) is framework-agnostic — only the integration layer touches framework-specific code

### Adding a Client Framework Hook

Currently supported: React, Vue, Svelte. To add another:

1. Create `client/src/your_framework/index.ts`
2. Implement the reactive wrapper around `AuthClient.onAuthStateChange`
3. Add the export path to `client/package.json` exports map
4. Add tests in `client/tests/`

## Code Style

### Python

- Use type hints for all function signatures
- No `from __future__ import annotations` in FastAPI endpoint files (breaks `Depends()`)
- Follow existing patterns — repositories take `AsyncSession`, core functions are framework-agnostic
- All datetime fields use `TZDateTime` type decorator (not bare `DateTime`)
- Use `utc_now()` from `authfort.utils` for timestamps

### TypeScript

- ESM modules — all internal imports must use `.js` extensions
- No default exports
- Framework hooks go in their own subdirectory (`react/`, `vue/`, `svelte/`)

### Tests

- pytest-asyncio in strict mode
- Use `pytestmark = pytest.mark.asyncio` at module level
- File-based SQLite for test isolation (not in-memory)
- Service tests use `_transport` injection (not monkeypatch)

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type: short description
```

| Type       | When to use                                |
| ---------- | ------------------------------------------ |
| `feat`     | New feature                                |
| `fix`      | Bug fix                                    |
| `docs`     | Documentation only                         |
| `refactor` | Code change that doesn't fix a bug or add feature |
| `test`     | Adding or updating tests                   |
| `chore`    | Maintenance (deps, CI, configs)            |

Breaking changes — add `!` after type:
```
feat!: change CookieConfig constructor signature
```

## Pull Request Process

### Branch Naming

- `feat/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation
- `chore/description` — Maintenance

### PR Checklist

Before submitting:

- [ ] Tests pass locally (`uv run pytest tests/ -v`)
- [ ] New features have tests
- [ ] No breaking changes without discussion
- [ ] Commit messages follow Conventional Commits
- [ ] PR description explains what and why

### Review Process

1. CI runs automatically (server, service, and client tests)
2. Maintainer reviews code and functionality
3. Changes requested or approved
4. Merged to main

## Design Philosophy

These principles guide what goes into AuthFort:

1. **Functions over routes** — Core auth operations are programmatic functions. Routes are optional (FastAPI integration). Developers wire their own endpoints for custom flows (password reset, email verification, etc.)

2. **No opinions on delivery** — AuthFort doesn't send emails, SMS, or push notifications. It generates tokens and verifies them. The developer handles delivery.

3. **No global singletons** — Everything lives on the `AuthFort` instance. Multiple instances in one process are supported.

4. **Stateless access tokens** — JWTs are valid until expiry. Session revocation takes effect at next refresh. Ban is the instant kill switch.

5. **Framework-agnostic core** — Core logic (`core/`) has zero framework dependencies. Integrations (`integrations/`) are thin wrappers.

## Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature request |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `documentation` | Docs improvements |
| `server` | Relates to authfort package |
| `service` | Relates to authfort-service package |
| `client` | Relates to authfort-client package |

## Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/bhagyajitjagdev/authfort/discussions)
- **Bugs**: Use [GitHub Issues](https://github.com/bhagyajitjagdev/authfort/issues)
- **Ideas**: Discuss before implementing large features

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for helping make AuthFort better!
