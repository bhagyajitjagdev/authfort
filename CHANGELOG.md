# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.27] - 2026-05-02

### Fixed
- **server**: `AuthFort(...)` now accepts `mfa_issuer` and `mfa_backup_code_count` kwargs and plumbs them into `AuthFortConfig`. The fields existed on the config dataclass since v0.0.22 but were never wired through the constructor, so `mfa_issuer` was effectively unreachable for SDK users — TOTP enrollment always used `jwt_issuer` regardless of what callers passed. `mfa_backup_code_count` was likewise stuck at the default 10.
- **server**: `AUTHFORT_TABLES` in `alembic_helper.py` now includes `authfort_user_mfa`, `authfort_mfa_backup_codes` (added in v0.0.22), and `authfort_password_history` (added in v0.0.25). These were missing from the registry, so apps using `register_foreign_tables` / `alembic_filters` for table-prefix isolation could have these tables incorrectly filtered out of AuthFort's migration scope.

### Upgrade notes
- No breaking changes. Apps that previously tried to pass `mfa_issuer=...` and got a `TypeError` will now work as documented.
- Apps using `alembic_filters` for table isolation should re-run `alembic revision --autogenerate` to confirm no spurious drops are detected for the three previously-missing tables.

## [0.0.26] - 2026-04-21

### Added
- **server**: `AuthFort.install_fastapi(app, prefix="/auth", jwks_prefix="", register_exception_handler=True)` — one-call FastAPI setup that mounts both routers AND registers a global `AuthError` → JSON response exception handler. Prevents `AuthError` from leaking through to downstream apps' generic 500 handlers. Opt out of the handler via `register_exception_handler=False`.
- **server**: `authfort.integrations.fastapi.authfort_exception_handler` — the handler is also exported for manual wiring via `app.add_exception_handler(AuthError, authfort_exception_handler)`.

### Fixed
- **server**: `email_deliverability_check=True` now applies to all email-input endpoints, not just signup. Previously, `/auth/magic-link`, `/auth/otp`, `/auth/login`, and the forgot-password path used the sync syntax-only validator and ignored the deliverability flag — meaning `k@k.k` could slip through when `allow_passwordless_signup=True`. (Follow-up to v0.0.25 VAPT response, caught in dev testing.)
- **server**: `/auth/magic-link` and `/auth/otp` endpoints now wrap `AuthError` in `try/except` and return 400 with the structured detail body, consistent with the other endpoints. Previously, `AuthError` raised from these two paths would escape the router as an unhandled exception.

### Upgrade notes
- Existing apps using `app.include_router(auth.fastapi_router(), prefix="/auth")` continue to work unchanged.
- Recommended migration: replace the two `include_router` calls with `auth.install_fastapi(app, prefix="/auth")`. Same behavior plus automatic `AuthError` handling.

## [0.0.25] - 2026-04-21

### Added
- **server**: HIBP (Have I Been Pwned) password breach check via k-anonymity — rejects passwords found in public breach corpora on signup, change, reset, and set-password. **Enabled by default**; fail-open on HIBP unreachable so outages don't block signups. Disable with `check_pwned_passwords=False`. Full password never leaves the process — only the first 5 chars of its SHA-1 travel to HIBP.
- **server**: Optional email deliverability (MX) check via `email_deliverability_check=True` (default off). When enabled, rejects emails whose domain has no MX record (e.g. `k@k.k`). Fail-open by default on DNS errors. Industry convention is to rely on email verification — enable this only if you need extra signup hygiene.
- **server**: Password history — opt-in via `password_history_count: int = 0` (default off). When set to N > 0, rejects password reuse of the last N passwords on change, reset, and set-password. New `authfort_password_history` table. Common values: 4 (PCI-DSS), 12 (SOC 2), 24 (FedRAMP).
- **server**: Refresh token cross-check — cookie-mode `/auth/refresh` now verifies the access_token cookie's `sub` and `sid` claims match the stored refresh token. On mismatch: revoke token, emit `RefreshTokenMismatch` event, return 401 `refresh_token_mismatch`. Defends against cookie-swap / session-fixation attempts. Bearer-mode unaffected.
- **server**: `refresh_token_mismatch` error code + `RefreshTokenMismatch` event
- **server**: `password_pwned` error code + `PasswordPwnedRejected` event (email stored as SHA-256 hash in the event)
- **server**: `password_reused` error code + `PasswordReuseRejected` event
- **server**: `password_unchanged` error code — `change_password` / `reset_password` now reject setting the new password equal to the current one
- **server**: New config options: `check_pwned_passwords` (default True), `pwned_check_fail_open`, `pwned_check_timeout`, `pwned_check_max_concurrency`, `pwned_check_cache_ttl`, `email_deliverability_check`, `email_deliverability_fail_open`, `password_history_count`
- **client**: Distinguishable `console.warn` on `refresh_token_mismatch` (cookie-swap defense triggered) so apps / error-tracking tools can separate this cause from ordinary session expiry. Behavior unchanged — still clears auth and transitions to unauthenticated.

### Changed
- **server**: `validate_user_email` now returns 400 `invalid_email` on any malformed input (previously could surface as 500 on certain edge cases — VAPT fix). All non-string / unicode-pathological inputs are now clean 400s.

### Migration
- **server**: New Alembic migration `004_add_password_history.py` — adds the `authfort_password_history` table. Run `alembic upgrade head`. Safe (empty table, no data migration).

### Upgrade notes
- **Default behavior change**: HIBP password check is on by default. Signup / password change with breached passwords will be rejected. Disable with `check_pwned_passwords=False` if needed. Fail-open ensures HIBP outages don't block signups.
- `k@k.k` and similar syntactically-legitimate-but-undeliverable emails continue to be accepted at signup by default. Enable `email_deliverability_check=True` for stricter validation, or rely on email verification (the canonical deliverability gate).
- No client or service breaking changes. Client error handling for `refresh_token_mismatch` behaves identically to other 401 responses (clears auth, transitions to unauthenticated — no retry).

## [0.0.24] - 2026-04-11

### Fixed
- **client**: `signInWithProvider` method signature now correctly returns `void | Promise<SignInResult>` to match the interface — fixes TypeScript build error

## [0.0.23] - 2026-04-10

### Added
- **server**: MFA is now enforced on OAuth logins — if a user has TOTP MFA enabled, `POST /oauth/{provider}/callback` returns an `MFAChallenge` instead of issuing tokens directly, consistent with password login
- **client**: `initialize()` detects `?mfa_token=` in the URL after an OAuth redirect and transitions to `mfa_pending` state automatically
- **client**: Popup OAuth flow (`signInWithProvider` with `mode: 'popup'`) now handles `MFAChallenge` from the server — resolves with `{ status: 'mfa_required' }` instead of a user

### Changed
- **client**: `signInWithProvider` popup mode return type changed from `Promise<AuthUser>` to `Promise<SignInResult>` to accommodate the MFA case

## [0.0.22] - 2026-04-10

### Added
- **server**: TOTP MFA (Google Authenticator, Authy) — `POST /auth/mfa/init`, `POST /auth/mfa/confirm`, `POST /auth/mfa/verify`, `POST /auth/mfa/disable`, `GET /auth/mfa/status`
- **server**: Backup codes — 10 single-use `xxxxx-xxxxx` codes generated on MFA enable, regeneratable via `POST /auth/mfa/backup-codes/regenerate`
- **server**: `mfa_enabled` claim added to all JWT access tokens — zero-latency posture checks in downstream services
- **server**: MFA challenge token — short-lived JWT (5 min) issued by `POST /login` when user has MFA enabled; submit to `POST /auth/mfa/verify` to complete login
- **server**: Replay protection — same TOTP code cannot be reused within the same 30s window
- **server**: `MFAEnabled`, `MFADisabled`, `MFALogin`, `MFAFailed`, `BackupCodeUsed`, `BackupCodesRegenerated` events
- **server**: `admin_disable_mfa(user_id)` — allows admins to forcibly disable MFA on a user account
- **server**: `mfa_issuer` config option — name shown in authenticator apps (defaults to `jwt_issuer`)
- **server**: `mfa_backup_code_count` config option — number of backup codes generated (default 10)
- **service**: `mfa_enabled` field on `TokenPayload` — read the claim from verified JWTs
- **client**: `'mfa_pending'` auth state — set after `signIn()` returns `{ status: 'mfa_required' }`
- **client**: `verifyMFA(code)` method on `AuthClient` — completes a two-step login
- **client**: `SignInResult` discriminated union — `signIn()` now returns `{ status: 'authenticated', user }` or `{ status: 'mfa_required' }`
- **client**: `mfaEnabled` field on `AuthUser` — reflects account-level MFA status from JWT
- **client**: `isMFAPending` in React hook, Vue composable, and Svelte store

### Dependencies
- **server**: Added `pyotp` (>=2.9.0) — TOTP generation and verification

## [0.0.21] - 2026-04-02

### Fixed
- **server**: Lower default `pool_recycle` from 3600s to 300s — prevents `ConnectionDoesNotExistError` when running behind PgBouncer or other connection poolers

### Added
- **server**: New `pool_recycle` config option on `AuthFort()` constructor — users can tune connection recycling interval (default 300s)

## [0.0.20] - 2026-03-31

### Added
- **server**: Input validation and sanitization for all user-facing fields (VAPT fix)
- **server**: Email validation using `email-validator` library — rejects SQL injection, XSS, header injection, XXE, and multi-email payloads
- **server**: Name and phone sanitization using `nh3` — strips all HTML tags (prevents stored XSS)
- **server**: Avatar URL validation — only `http://` and `https://` URLs accepted
- **server**: Minimum password length enforcement (configurable via `min_password_length`, default 8)
- **server**: New `min_password_length` config option on `AuthFort()` constructor
- **server**: `AuthError` moved to `authfort.core.errors` module (re-exported from `authfort.core.auth` — no breaking changes)
- 60 new validation tests (541 total)

### Dependencies
- **server**: Added `email-validator` (>=2.3.0) — RFC-compliant email validation
- **server**: Added `nh3` (>=0.3.4) — Rust-based HTML sanitization

## [0.0.19] - 2026-03-12

### Added
- **server**: `set_password(user_id, new_password)` — passwordless users (magic link, OTP, OAuth) can set an initial password
- **server**: `POST /auth/set-password` REST endpoint (authenticated) for setting initial password
- **server**: `PasswordSet` event — fired when a passwordless user sets their initial password
- **server**: `create_password_reset_token()` now works for all users — passwordless and OAuth users can use forgot-password to set their initial password
- **server**: `reset_password()` automatically creates an `email` account record when setting a first-time password

### Fixed
- **server**: Passwordless users (magic link, OTP) no longer get the misleading "This account uses social login" error — they now get a `no_password` error code with a message guiding them to `set-password` or forgot-password
- **server**: `change_password()` now distinguishes OAuth users (`oauth_account` code with providers list) from passwordless users (`no_password` code)
- **server**: Banned user check in `login()` moved after password verification — prevents attackers from probing for banned accounts without knowing the password

## [0.0.18] - 2026-03-03

### Added
- **server**: `create_user(email_verified=True)` — mark email as verified at creation time (e.g., admin-created accounts that skip email verification)
- **server**: `update_user(user_id, email_verified=True)` — admin can manually verify or unverify a user's email
- **server**: `EmailVerified` event fires automatically when `email_verified=True` is set via `create_user()` or `update_user()` (no duplicate event if user is already verified)
- 11 new server tests (491 total)

## [0.0.17] - 2026-02-28

### Added
- **server**: `trust_proxy` config — trust `X-Forwarded-For` / `X-Real-IP` headers from any source (simple mode for single-proxy setups)
- **server**: `trusted_proxies` config — only trust proxy headers from listed IPs/CIDRs, e.g. `["172.18.0.0/16"]` (recommended for production, prevents spoofing)
- **server**: Centralized `get_client_ip()` helper replaces 12 inline `request.client.host` calls across all auth and OAuth endpoints
- **server**: CIDR networks parsed once at startup via Python `ipaddress` module (zero per-request overhead)
- **server**: Stable `session_id` across refresh token rotation — `session_id` in JWT (`sid` claim) no longer changes on every refresh, fixing session list UIs that showed phantom entries after each token rotation
- **server**: New migration `002_add_session_id` — adds `session_id` column to `authfort_refresh_tokens` (run `authfort migrate` to apply)
- **server**: `get_sessions()` now deduplicates by `session_id` — returns one entry per logical session instead of one per refresh token
- **server**: `revoke_session()` and `revoke_all_sessions(exclude=...)` now operate on `session_id` — revoking a session invalidates all tokens in its rotation chain

### Fixed
- **client**: Cookie-mode refresh deduplication — multiple concurrent 401 responses now share a single `/refresh` call instead of each firing their own (fixes phantom sessions and wasted refresh token rotations)

## [0.0.16] - 2026-02-28

### Fixed
- **server**: `change_password()` now returns 400 (not 401) for wrong old password — the request is already authenticated via access token, so a wrong confirmation field is a validation error, not an auth failure. Prevents `authfort-client` from triggering a useless 401 retry loop.
- **server**: Login on OAuth-only account now returns 400 (not 401) with `oauth_account` code — the user is identified but using the wrong auth method, which is a bad request, not an authentication failure.

## [0.0.15] - 2026-02-28

### Added
- **server**: `authfort migrate` CLI command — run migrations without a bootstrap script (`uvx authfort migrate --database-url "..."`)
- **server**: `register_foreign_tables(metadata)` — register AuthFort table stubs for FK resolution in consumer models
- **server**: `alembic_filters()` — returns both `include_name` and `include_object` filters for `context.configure(**alembic_filters())`

### Removed
- **server**: `alembic_exclude()` — replaced by `alembic_filters()`

## [0.0.14] - 2026-02-28

### Fixed
- **server**: Boolean column defaults in migration use `false` instead of `0` — fixes PostgreSQL table creation failure (`0` is not a valid boolean literal in Postgres)

## [0.0.13] - 2026-02-28

### Added
- **server**: `AuthUser` and `AuthUserRole` exports — exposes SQLAlchemy `User` and `UserRole` models for ORM JOINs against consumer tables

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

[0.0.27]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.26...v0.0.27
[0.0.26]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.25...v0.0.26
[0.0.25]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.24...v0.0.25
[0.0.18]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.17...v0.0.18
[0.0.17]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.16...v0.0.17
[0.0.16]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.15...v0.0.16
[0.0.15]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.14...v0.0.15
[0.0.14]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.13...v0.0.14
[0.0.13]: https://github.com/bhagyajitjagdev/authfort/compare/v0.0.12...v0.0.13
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
