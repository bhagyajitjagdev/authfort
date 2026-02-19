# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-02-18

### Fixed
- **client**: Added `.js` extensions to all ESM internal imports (required by Node.js ESM resolution)
- **service**: Fixed JWKS rate limiting — `_last_fetch_attempt` initialized to `-inf` instead of `0.0` (failed on fresh CI VMs where `time.monotonic() < 60s`)
- **service**: Replaced fragile `httpx.AsyncClient.__init__` monkeypatch in tests with `_transport` injection
- **server/service**: Moved `dependencies` above `[project.urls]` in `pyproject.toml` (TOML ordering caused hatchling build failure)

### Added
- **server**: Exported `UserResponse` and `AuthResponse` from top-level `__init__.py`
- **client**: Added `"files": ["dist"]` to `package.json` (only publishes built files to npm)
- CI/CD pipeline: `ci.yml` (tests on PR/push) + `release.yml` (publish on tag push)

## [0.0.2] - 2026-02-18

### Fixed
- Version bump after `0.0.1` was burned on npm (npm doesn't allow republishing)

## [0.0.1] - 2026-02-18

### Added
- **Core Auth**: Email/password signup and login with argon2 password hashing
- **JWT RS256**: Stateless access tokens with automatic RSA key pair management
- **Refresh Token Rotation**: Secure rotation with theft detection (token family tracking)
- **Cookie & Bearer Modes**: HttpOnly cookie delivery or Authorization header
- **OAuth 2.1 + PKCE**: Google and GitHub providers with automatic account linking by email
- **Role-Based Access Control**: `add_role`, `remove_role`, `get_roles`, `require_role` dependency
- **Session Management**: List sessions, revoke individual, revoke all for a user
- **Ban/Unban**: Instant invalidation via `token_version` bump + session revocation
- **Event Hooks**: 12 event types — `user_created`, `login`, `login_failed`, `logout`, `oauth_link`, `role_added`, `role_removed`, `user_banned`, `user_unbanned`, `session_revoked`, `token_refreshed`, `key_rotated`
- **JWKS Endpoint**: `/.well-known/jwks.json` with automatic key rotation and TTL-based cleanup
- **Token Introspection**: RFC 7662 endpoint with shared secret authentication
- **Programmatic API**: `create_user`, `login`, `refresh`, `logout` on AuthFort instance
- **Signup Control**: `allow_signup=False` to disable public registration
- **Email Validation**: Basic format regex + normalization (strip + lowercase)
- **Multi-Database**: PostgreSQL (primary, asyncpg), SQLite (aiosqlite), MySQL (aiomysql)
- **Database Adapters**: Conditional engine settings per dialect (pool settings, `check_same_thread`)
- **TZDateTime**: TypeDecorator ensuring timezone-aware datetimes across all backends
- **FastAPI Integration**: Auth router, OAuth router, JWKS router, introspect router, `current_user` + `require_role` dependencies
- **authfort-service**: Lightweight JWT verifier — JWKS fetcher with cache/rate-limiting, token introspection client with fail-open/fail-closed modes
- **authfort-client**: TypeScript SDK — `createAuthClient`, `auth.fetch()`, `auth.signIn/signUp/signOut`, `auth.initialize()`, `getToken()`, `onAuthStateChange`
- **React Integration**: `AuthProvider` + `useAuth()` hook
- **Vue Integration**: `provideAuth()` + `useAuth()` composable
- **Svelte Integration**: `createAuthStore()` with reactive stores
- MIT License
- README for all packages

[0.0.3]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/bhagyajitjagdev/authfort/releases/tag/v0.0.1
