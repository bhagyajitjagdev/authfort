# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.12] - 2026-02-28

### Added
- **server**: `banned` field on `UserResponse` — visible in all user responses (login, signup, get_user, list_users, current_user)

## [0.0.11] - 2026-02-28

### Added
- **server**: `RateLimitConfig` — optional per-endpoint rate limits (`"5/min"` format) with in-memory sliding window counter
- **server**: IP-based rate limiting on all 8 auth endpoints (login, signup, refresh, magic-link, otp, otp/verify, verify-email, oauth/authorize)
- **server**: Email-based rate limiting on login, signup, magic-link, otp, otp/verify (catches distributed attacks)
- **server**: 429 response with `Retry-After` header on rate limit exceeded
- **server**: `RateLimitExceeded` event with endpoint, IP, email, limit, key_type
- **server**: `RateLimitStore` protocol — pluggable for Redis or other backends
- **server**: `auth.list_users()` — paginated listing with `query` (case-insensitive email/name search), `banned`, `role` filters, `sort_by`/`sort_order`
- **server**: `auth.get_user(user_id)` — single user lookup, returns `UserResponse` with roles
- **server**: `auth.delete_user(user_id)` — application-level cascade delete (roles → tokens → accounts → verification tokens → user)
- **server**: `auth.get_user_count()` — count with same query/banned/role filters
- **server**: `ListUsersResponse` schema (users, total, limit, offset)
- **server**: `UserDeleted` event with user_id and email
- **server**: `ondelete="CASCADE"` on all user foreign keys
- **server**: `RateLimitConfig`, `RateLimitExceeded`, `ListUsersResponse`, `UserDeleted` exported from top-level
- 62 new server tests (424 total), 92% coverage maintained

## [0.0.10] - 2026-02-23

### Added
- **server**: Email verification flow — `create_email_verification_token(user_id)`, `verify_email(token)`
- **server**: Magic link passwordless login — `create_magic_link_token(email)`, `verify_magic_link(token)`
- **server**: Email OTP passwordless login — `create_email_otp(email)`, `verify_email_otp(email, code)`
- **server**: `GenericOAuthProvider` — connect any OAuth 2.0 provider with custom endpoints
- **server**: `GenericOIDCProvider` — connect any OpenID Connect provider via discovery URL
- **server**: `allow_passwordless_signup` config — auto-create users via magic link/OTP for unknown emails
- **server**: `email_verify_ttl`, `magic_link_ttl`, `email_otp_ttl` config params
- **server**: 5 new FastAPI endpoints — `/magic-link`, `/magic-link/verify`, `/otp`, `/otp/verify`, `/verify-email`
- **server**: 6 new events — `email_verification_requested`, `email_verified`, `magic_link_requested`, `magic_link_login`, `email_otp_requested`, `email_otp_login`
- **server**: Custom user info mapper support for generic OAuth providers
- **server**: OIDC discovery caching with configurable TTL
- **client**: `requestMagicLink(email)`, `verifyMagicLink(token)` methods
- **client**: `requestOTP(email)`, `verifyOTP(email, code)` methods
- **client**: `verifyEmail(token)` method — updates local `emailVerified` state
- **client**: `OAuthProvider` type accepts any string for generic providers (`'google' | 'github' | (string & {})`)
- 59 new server tests, 14 new client tests (469 total)

## [0.0.9] - 2026-02-20

### Added
- **server**: `auth.has_role(user_id, role)` — convenience method for single-role checks
- **server**: `auth.get_jwks()` — returns JWKS dict for non-FastAPI frameworks (Django, Flask, etc.)
- **server**: `auth.cleanup_expired_sessions()` — deletes expired and revoked refresh tokens
- **server**: `auth.update_user(user_id, *, name, avatar_url, phone)` — update user profile fields programmatically
- **server**: `auth.get_provider_tokens(user_id, provider)` — retrieve stored OAuth provider tokens (access + refresh)
- **server**: `phone` column on User model — optional phone number field
- **server**: `avatar_url` and `phone` params on `create_user()` and `/auth/signup` endpoint
- **server**: `rsa_key_size` config param (default 2048, must be >= 2048) — configurable RSA key size for JWT signing
- **server**: `frontend_url` config param — prepends frontend origin to OAuth `redirect_to` paths for cross-origin setups
- **server**: OAuth `redirect_to` query param — redirect users to a specific path after OAuth callback
- **server**: OAuth `mode=popup` — callback returns HTML with `postMessage` for SPA popup flows
- **server**: OAuth `extra_scopes` param on providers — request additional provider API scopes beyond required ones
- **server**: OAuth provider token storage — `access_token` and `refresh_token` from providers are now saved on callback
- **server**: `UserUpdated` event — fired when `update_user()` modifies profile fields
- **server**: `AuthTokens` added to public exports
- **server**: All 16 event classes exported from top-level `__init__.py`
- **client**: `OAuthProvider` type (`'google' | 'github'`) for typed provider params
- **client**: `OAuthSignInOptions` — `mode` (`'redirect' | 'popup'`) and `redirectTo` options for `signInWithProvider()`
- **client**: OAuth popup mode — opens popup window, returns `Promise<AuthUser>` via `postMessage`
- **client**: `signUp()` accepts `avatarUrl` and `phone` optional fields
- **client**: Auto-initialize in React `AuthProvider`, Vue `provideAuth()`, and Svelte `createAuthStore()`

### Changed
- **server**: OAuth providers use `extra_scopes` instead of `scopes` — required scopes (`REQUIRED_SCOPES`) are always included automatically
- **server**: `get_jwks()` extracted from JWKS router — router now delegates to the method (DRY)
- **server**: `jwt_algorithm` removed from constructor and config — RS256 is the only supported algorithm, now a module constant `JWT_ALGORITHM`

### Removed
- **server**: `jwt_algorithm` config parameter — hardcoded to RS256 (key size is what's configurable via `rsa_key_size`)

### Fixed
- **server**: OAuth provider `refresh_token` was never saved — now extracted from `exchange_code()` response and stored on Account

## [0.0.8] - 2026-02-19

### Breaking
- **server**: Replaced `sqlmodel` dependency with `sqlalchemy[asyncio]>=2.0` — developers using `sqlmodel` imports from AuthFort internals must update
- **server**: Bundled migrations reset to single `001_initial_schema.py` — existing dev databases need a fresh `auth.migrate()` (drop old DB first)

### Changed
- **server**: All models now use SQLAlchemy `DeclarativeBase` + `Mapped[type]` + `mapped_column()` instead of SQLModel
- **server**: All repositories use `session.execute().scalars()` instead of `session.exec()`
- **server**: `AsyncSession` imported from `sqlalchemy.ext.asyncio` instead of `sqlmodel.ext.asyncio.session`
- **server**: Developer Alembic `env.py` uses `Base.metadata` instead of `SQLModel.metadata`
- **server**: Developer migration uses `sa.String()` / `sa.Text()` instead of `sqlmodel.sql.sqltypes.AutoString`
- **server**: `models/__init__.py` now exports `Base` for Alembic and test usage

### Removed
- **server**: `sqlmodel` dependency — replaced by direct `sqlalchemy[asyncio]>=2.0`
- **server**: Bundled migration `002_composite_index.py` — merged into `001_initial_schema.py`

### Fixed
- **server**: Eliminated 85 false SQLModel deprecation warnings in pytest

## [0.0.7] - 2026-02-19

### Fixed
- **server**: OAuth ban check — banned users can no longer login via OAuth providers
- **server**: OAuth email normalization — provider emails are now lowercased before lookup, preventing duplicate accounts
- **server**: OAuth concurrent signup — `IntegrityError` on duplicate email is caught gracefully instead of crashing
- **server**: Atomic `bump_token_version()` — uses SQL-level increment to prevent race conditions under concurrent load
- **server**: Atomic `ban_user()` — uses SQL-level update for banned flag and token_version
- **server**: Atomic `revoke_all_user_refresh_tokens()` — single UPDATE statement prevents tokens created mid-revocation from surviving
- **server**: Atomic signing key deactivation — prevents race condition during concurrent key rotation
- **server**: Introspection now checks session validity via `sid` claim — revoked sessions return `active: false`
- **server**: Password change and reset now revoke all refresh tokens (prevents auto-recovery via refresh)
- **service**: Introspection cache uses hashed token keys instead of raw tokens for privacy

### Added
- **server**: OAuth `login_failed` events fired on all error paths (provider error, missing params, state invalid, auth failure)
- **server**: `auth.cleanup_expired_tokens()` — deletes expired verification tokens to prevent database bloat
- **server**: Migration `002_composite_index` — composite index on `refresh_tokens(user_id, revoked)` for query performance
- **server**: `get_refresh_token_by_id()` repository function for session validity lookups

### Changed
- **server**: Default test database changed from PostgreSQL to SQLite (no external DB needed to run tests)

## [0.0.6] - 2026-02-19

### Breaking
- All database tables renamed with `authfort_` prefix (requires fresh DB or manual rename)
- `SQLModel.metadata.create_all()` replaced by `await auth.migrate()` at app startup

### Added
- **server**: `auth.migrate()` — bundled Alembic migrations, safe to rerun, tracks state in `authfort_alembic_version`
- **server**: `alembic_exclude()` — helper for devs sharing a DB, filters `authfort_*` tables from Alembic autogenerate
- **server**: `CookieConfig(domain=".example.com")` — subdomain cookie sharing for multi-service architectures
- **service**: `ServiceAuth(cookie_name="access_token")` — cookie fallback when no Bearer header present

### Changed
- Table names: `users` → `authfort_users`, `accounts` → `authfort_accounts`, `refresh_tokens` → `authfort_refresh_tokens`, `user_roles` → `authfort_user_roles`, `signing_keys` → `authfort_signing_keys`, `verification_tokens` → `authfort_verification_tokens`

## [0.0.5] - 2026-02-19

### Fixed
- **server**: `RefreshRequest.refresh_token` now optional — fixes 422 when client sends empty body with cookie

### Changed
- **client**: **Breaking (bearer mode only):** `tokenMode: 'bearer'` now requires `tokenStorage` option
- **client**: Bearer mode sends refresh token in request body (no longer relies on cookies)
- **client**: Bearer mode `fetch()` no longer sends `credentials: 'include'`

### Added
- **client**: `TokenStorage` interface — pluggable storage adapter for refresh tokens in bearer mode
- **client**: Works with any storage: `localStorage`, `expo-secure-store`, `react-native-keychain`, etc.

## [0.0.4] - 2026-02-19

### Added
- **server**: `create_password_reset_token(email)` — generates opaque reset token (returns `None` for unknown/OAuth-only users to prevent enumeration)
- **server**: `reset_password(token, new_password)` — one-time use, bumps `token_version` to invalidate all existing JWTs
- **server**: `change_password(user_id, old_password, new_password)` — verifies old password, bumps `token_version`
- **server**: `revoke_all_sessions(user_id, *, exclude=session_id)` — new `exclude` param to keep current session alive
- **server**: `session_id` field on `UserResponse` — embedded in JWT as `sid` claim, available via `current_user` dependency
- **server**: `password_reset_ttl` config param (default 1 hour)
- **server**: 3 new events: `password_reset_requested`, `password_reset`, `password_changed`
- **server**: 28 new tests (198 total)

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

[0.0.12]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.11...v0.0.12
[0.0.11]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/bhagyajitjagdev/authfort/releases/tag/v0.0.1
