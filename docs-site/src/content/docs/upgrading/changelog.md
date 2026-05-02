---
title: Changelog
description: Version history and breaking changes.
sidebar:
  order: 1
---

All notable changes to AuthFort are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## v0.0.27

### Fixed
- **`AuthFort(...)` now accepts `mfa_issuer` and `mfa_backup_code_count`** — both fields existed on `AuthFortConfig` since v0.0.22 but were never plumbed through the constructor, so they couldn't be set by SDK users. `mfa_issuer` silently fell back to `jwt_issuer` for TOTP enrollment regardless of what callers passed.
- **`AUTHFORT_TABLES` registry now includes the MFA and password-history tables** — `authfort_user_mfa`, `authfort_mfa_backup_codes` (added v0.0.22), and `authfort_password_history` (added v0.0.25) were missing from the registry. Apps using `register_foreign_tables` / `alembic_filters` for table-prefix isolation could have these tables incorrectly filtered out of AuthFort's migration scope.

### Upgrade note
No breaking changes. Apps that previously hit a `TypeError` trying to pass `mfa_issuer` will now work as the docs describe. Apps using `alembic_filters` should re-run `alembic revision --autogenerate` to confirm no spurious drops are detected for the previously-missing tables.

---

## v0.0.26

### Added
- **One-line FastAPI integration** — `auth.install_fastapi(app, prefix="/auth")` mounts both routers and registers a global `AuthError` exception handler so errors always surface as clean 4xx with a structured body, never leaking through to the downstream app's 500 handler.
- `authfort.integrations.fastapi.authfort_exception_handler` exported for manual wiring via `app.add_exception_handler(...)`.

### Fixed
- **`email_deliverability_check=True` now gates magic-link, OTP, login, and forgot-password** — not just signup. `k@k.k` submitted to `/auth/magic-link` with `allow_passwordless_signup=True` previously slipped through; now correctly rejected with 400 `invalid_email`.
- `/auth/magic-link` and `/auth/otp` endpoints now return 400 on invalid email input instead of letting the exception escape as 500.

### Upgrade note
Existing `app.include_router(auth.fastapi_router(), prefix="/auth")` keeps working. Recommended: switch to `auth.install_fastapi(app, prefix="/auth")` for automatic error handling.

---

## v0.0.25

### Added
- **HIBP breach check** — password-setting endpoints reject passwords found in the Have I Been Pwned corpus via k-anonymity. Enabled by default; fail-open so HIBP outages don't block signups. Disable with `check_pwned_passwords=False` if you need to.
- **Refresh token cross-check** — cookie-mode `/auth/refresh` now verifies the access token's `sub` and `sid` claims match the stored refresh token. Defends against cookie-swap attempts. Returns 401 `refresh_token_mismatch` and revokes the refresh token on failure.
- **Password history** (opt-in) — set `password_history_count=N` to prevent reuse of the last N passwords. Common values: 4 (PCI-DSS), 12 (SOC 2), 24 (FedRAMP). Adds the `authfort_password_history` table.
- **Optional email deliverability check** — set `email_deliverability_check=True` to require MX records at signup. Default off; the canonical deliverability gate remains email verification.
- **No-op password change rejected** — setting a new password equal to the current one returns 400 `password_unchanged`.
- **Defensive email validation** — `validate_user_email` now returns 400 on any malformed input (previously could surface 500 on pathological inputs).

### Events
- `PasswordPwnedRejected` (email stored as SHA-256 hash)
- `RefreshTokenMismatch`
- `PasswordReuseRejected`

### Migration
- New Alembic migration `004_add_password_history.py` — run `alembic upgrade head`. Empty table, no data migration.

### Client SDK
- Distinguishable `console.warn` when `/refresh` fails with `refresh_token_mismatch`, so apps can tell cookie-swap defense triggers apart from ordinary session expiry. No behavior change — still clears auth.

### Upgrade notes
HIBP check is **on by default**. If your app flows rely on specific weak passwords (e.g., test data, demo accounts), disable via `check_pwned_passwords=False` before upgrading.

---

## v0.0.24

### Fixed
- **client**: TypeScript build error — `signInWithProvider` method signature now matches the `AuthClient` interface

---

## v0.0.23

### Added
- **MFA enforced on OAuth login** — if a user has TOTP MFA enabled, logging in via Google, GitHub, or any OAuth provider now triggers the same MFA challenge as password login
- **Client** `initialize()` detects `?mfa_token=` in the URL after an OAuth redirect and transitions to `mfa_pending` automatically — no extra code needed in your app
- **Client** Popup OAuth flow (`signInWithProvider` with `mode: 'popup'`) now resolves with `{ status: 'mfa_required' }` when the account has MFA enabled

### Breaking Changes
- **Client** `signInWithProvider` popup mode return type changed from `Promise<AuthUser>` to `Promise<SignInResult>` — update any popup mode callers to check `result.status`

---

## v0.0.22

### Added
- **TOTP MFA** — Google Authenticator, Authy, and any RFC 6238-compatible app
  - `POST /auth/mfa/init` — generate secret + QR URI
  - `POST /auth/mfa/confirm` — enable MFA, receive backup codes
  - `POST /auth/mfa/verify` — complete two-step login with TOTP or backup code
  - `POST /auth/mfa/disable` — disable MFA (requires current TOTP or backup code)
  - `POST /auth/mfa/backup-codes/regenerate` — new set of backup codes
  - `GET /auth/mfa/status` — current MFA status and remaining backup code count
- **`mfa_enabled` JWT claim** — all access tokens carry this flag; downstream services can check posture with zero latency
- **MFA challenge token** — `POST /login` returns `{ mfa_required: true, mfa_token }` when MFA is enabled; submit to `/mfa/verify` to receive full tokens
- **Replay protection** — same TOTP code blocked within the same 30s window
- **Admin** `admin_disable_mfa(user_id)` — forcibly disable MFA on any account
- **Config** `mfa_issuer` — authenticator app display name (defaults to `jwt_issuer`)
- **Config** `mfa_backup_code_count` — number of backup codes per user (default 10)
- **Service** `TokenPayload.mfa_enabled` — parsed from the `mfa_enabled` JWT claim
- **Client** `signIn()` now returns `SignInResult` — `{ status: 'authenticated', user }` or `{ status: 'mfa_required' }`
- **Client** `verifyMFA(code)` — complete a pending MFA login
- **Client** `isMFAPending` in React hook, Vue composable, and Svelte store
- **Client** `AuthUser.mfaEnabled` — account-level MFA status
- **Events** `MFAEnabled`, `MFADisabled`, `MFALogin`, `MFAFailed`, `BackupCodeUsed`, `BackupCodesRegenerated`

### Breaking Changes
- **Client** `signIn()` return type changed from `Promise<AuthUser>` to `Promise<SignInResult>` — update callers to check `result.status`

### Dependencies
- **server**: `pyotp >= 2.9.0` — run `uv add pyotp` in `server/`

---

## v0.0.21

### Fixed
- Default `pool_recycle` lowered from 3600s to 300s — prevents `ConnectionDoesNotExistError` behind PgBouncer

### Added
- New `pool_recycle` config option on `AuthFort()` — tune connection recycling interval (default 300s)

---

## v0.0.20

### Added
- Input validation and sanitization for all user-facing fields (VAPT fix)
- Email validation using `email-validator` — rejects SQL injection, XSS, header injection, XXE payloads
- Name and phone sanitization using `nh3` — strips all HTML tags (prevents stored XSS)
- Avatar URL validation — only `http://` and `https://` URLs accepted
- Minimum password length enforcement (`min_password_length` config, default 8)
- New dependencies: `email-validator` (>=2.3.0), `nh3` (>=0.3.4)

---

## v0.0.19

### Added
- `set_password(user_id, new_password)` — passwordless users (magic link, OTP, OAuth) can set an initial password
- `POST /auth/set-password` REST endpoint (authenticated)
- `PasswordSet` event fired when a passwordless user sets their initial password
- `create_password_reset_token()` now works for all users — passwordless/OAuth users can use forgot-password to set a password

### Fixed
- Passwordless users no longer get misleading "social login" error — new `no_password` error code guides them correctly
- `change_password()` distinguishes OAuth (`oauth_account`) from passwordless (`no_password`) users
- Banned check in `login()` moved after password verification (security: prevents banned-account probing)

---

## v0.0.18

### Added
- `create_user(email_verified=True)` — mark email as verified at creation time (admin-created accounts)
- `update_user(user_id, email_verified=True)` — admin can manually verify or unverify a user's email
- `EmailVerified` event fires automatically on verification via `create_user()` or `update_user()` (no duplicate if already verified)

---

## v0.0.17

### Added
- `trust_proxy` config — trust `X-Forwarded-For` / `X-Real-IP` from any source
- `trusted_proxies` config — only trust proxy headers from listed IPs/CIDRs (recommended for production)
- Centralized IP extraction across all auth and OAuth endpoints
- Stable `session_id` across refresh token rotation — JWT `sid` claim no longer changes on refresh
- Migration `002_add_session_id` — adds `session_id` column (run `authfort migrate` to apply)
- `get_sessions()` deduplicates by `session_id` — one entry per logical session
- `revoke_session()` and `revoke_all_sessions(exclude=...)` operate on stable `session_id`

### Fixed
- **client**: Cookie-mode refresh deduplication — concurrent 401s share a single `/refresh` call

---

## v0.0.16

### Fixed
- `change_password()` returns 400 (not 401) for wrong old password — prevents client SDK 401 retry loop
- Login on OAuth-only account returns 400 (not 401) with `oauth_account` code — wrong auth method is a bad request, not an auth failure

---

## v0.0.15

### Added
- `authfort migrate` CLI command — run migrations without a bootstrap script (`uvx authfort migrate --database-url "..."`)
- `register_foreign_tables(metadata)` — register AuthFort table stubs for FK resolution in consumer models
- `alembic_filters()` — returns both `include_name` and `include_object` filters for `context.configure(**alembic_filters())`

### Removed
- `alembic_exclude()` — replaced by `alembic_filters()`

---

## v0.0.14

### Fixed
- Boolean column defaults in migration use `false` instead of `0` — fixes PostgreSQL table creation failure

---

## v0.0.13

### Added
- `AuthUser` and `AuthUserRole` exports — SQLAlchemy models for ORM JOINs against consumer tables

---

## v0.0.12

### Added
- `banned` field on `UserResponse` — visible in all user responses (login, signup, get_user, list_users, current_user)

---

## v0.0.11

### Added
- `RateLimitConfig` — per-endpoint rate limits (`"5/min"` format) with in-memory sliding window
- IP-based rate limiting on all 8 auth endpoints
- Email-based rate limiting on login, signup, magic-link, otp, otp/verify (catches distributed attacks)
- 429 + `Retry-After` header on rate limit exceeded
- `RateLimitExceeded` event with endpoint, IP, email, limit, key_type
- `RateLimitStore` protocol — pluggable for Redis or other backends
- `auth.list_users()` — paginated listing with query/banned/role filters, sort_by/sort_order
- `auth.get_user(user_id)` — single user lookup with roles
- `auth.delete_user(user_id)` — cascade delete (roles → tokens → accounts → verification tokens → user)
- `auth.get_user_count()` — count with same filters
- `ListUsersResponse` schema, `UserDeleted` event
- `ondelete="CASCADE"` on all user foreign keys
- `RateLimitConfig`, `RateLimitExceeded`, `ListUsersResponse`, `UserDeleted` exported from top-level

---

## v0.0.10

### Added
- Email verification flow — `create_email_verification_token()` / `verify_email()`
- Magic link passwordless login — `create_magic_link_token()` / `verify_magic_link()`
- Email OTP passwordless login — `create_email_otp()` / `verify_email_otp()`
- `GenericOAuthProvider` — connect any OAuth 2.0 provider with custom endpoints
- `GenericOIDCProvider` — connect any OIDC provider via discovery URL
- `allow_passwordless_signup` config — auto-create users for unknown emails via magic link/OTP
- `email_verify_ttl`, `magic_link_ttl`, `email_otp_ttl` config params
- 5 new endpoints: `/magic-link`, `/magic-link/verify`, `/otp`, `/otp/verify`, `/verify-email`
- 6 new events: `email_verification_requested`, `email_verified`, `magic_link_requested`, `magic_link_login`, `email_otp_requested`, `email_otp_login`
- **client**: `requestMagicLink()`, `verifyMagicLink()`, `requestOTP()`, `verifyOTP()`, `verifyEmail()` methods
- **client**: `OAuthProvider` type accepts any string for generic providers

---

## v0.0.9

### Added
- `auth.has_role(user_id, role)` — single-role convenience check
- `auth.get_jwks()` — JWKS dict for non-FastAPI frameworks
- `auth.cleanup_expired_sessions()` — delete expired/revoked sessions
- `auth.update_user(user_id, *, name, avatar_url, phone)` — update profile fields
- `auth.get_provider_tokens(user_id, provider)` — retrieve stored OAuth tokens
- `phone` field on User model, `create_user()`, and `/auth/signup`
- `rsa_key_size` config — configurable RSA key size (default 2048)
- `frontend_url` config — cross-origin OAuth redirect support
- OAuth `redirect_to` query param — redirect after callback
- OAuth `mode=popup` — popup flow with `postMessage`
- OAuth `extra_scopes` — request additional provider API scopes
- OAuth provider token storage — saves `access_token` and `refresh_token` from providers
- `UserUpdated` event — fired on profile update
- `AuthTokens` added to public exports
- All 16 event classes exported from top-level
- **client**: `OAuthProvider` type, `OAuthSignInOptions`, popup mode, `avatarUrl`/`phone` in `signUp()`
- **client**: Auto-initialize in React, Vue, and Svelte integrations

### Changed
- OAuth providers use `extra_scopes` instead of `scopes` — required scopes always included
- `jwt_algorithm` removed — RS256 is hardcoded (use `rsa_key_size` for key strength)

### Fixed
- OAuth provider `refresh_token` was never saved — now stored on callback

---

## v0.0.8

### Breaking
- **server**: Replaced `sqlmodel` dependency with `sqlalchemy[asyncio]>=2.0`
- **server**: Bundled migrations reset to single `001_initial_schema.py` — existing dev databases need a fresh `auth.migrate()` (drop old DB first)

### Changed
- All models use SQLAlchemy `DeclarativeBase` + `mapped_column()` instead of SQLModel
- All repositories use `session.execute().scalars()` instead of `session.exec()`
- `models/__init__.py` exports `Base` for Alembic and test usage

### Removed
- `sqlmodel` dependency
- Bundled migration `002_composite_index.py` (merged into 001)

### Fixed
- Eliminated 85 false SQLModel deprecation warnings in pytest

---

## v0.0.7

### Fixed
- OAuth ban check — banned users can no longer login via OAuth
- OAuth email normalization — provider emails are lowercased before lookup
- OAuth concurrent signup — `IntegrityError` on duplicate email is caught gracefully
- Atomic `bump_token_version()`, `ban_user()`, `revoke_all_user_refresh_tokens()`, signing key deactivation
- Introspection checks session validity via `sid` claim
- Password change and reset now revoke all refresh tokens

### Added
- OAuth `login_failed` events fired on all error paths
- `auth.cleanup_expired_tokens()` for verification token cleanup
- Migration `002_composite_index` for query performance
- `get_refresh_token_by_id()` repository function

---

## v0.0.6

### Breaking
- All database tables renamed with `authfort_` prefix (requires fresh DB)
- `SQLModel.metadata.create_all()` replaced by `await auth.migrate()`

### Added
- `auth.migrate()` — bundled Alembic migrations
- `alembic_exclude()` — filter AuthFort tables from your Alembic autogenerate
- `CookieConfig(domain=".example.com")` — subdomain cookie sharing
- `ServiceAuth(cookie_name="access_token")` — cookie fallback

---

## v0.0.5

### Fixed
- `RefreshRequest.refresh_token` now optional — fixes 422 when client sends empty body with cookie

### Changed
- **client**: Bearer mode sends refresh token in request body
- **client**: Bearer mode `fetch()` no longer sends `credentials: 'include'`

### Added
- **client**: `TokenStorage` interface — pluggable storage for bearer mode

---

## v0.0.4

### Added
- `create_password_reset_token(email)` — generate reset token
- `reset_password(token, new_password)` — one-time use reset
- `change_password(user_id, old_password, new_password)` — authenticated change
- `revoke_all_sessions(user_id, *, exclude=session_id)` — keep current session
- `session_id` on `UserResponse` (from `sid` JWT claim)
- `password_reset_ttl` config param
- 3 new events: `password_reset_requested`, `password_reset`, `password_changed`

---

## v0.0.3

### Fixed
- ESM imports in client SDK (added `.js` extensions)
- JWKS rate limiting (`_last_fetch_attempt` initialized to `-inf`)
- `dependencies` placement in `pyproject.toml`

### Added
- Exported `UserResponse` and `AuthResponse` from top-level
- `"files": ["dist"]` in client `package.json`
- CI/CD pipeline (`ci.yml` + `release.yml`)

---

## v0.0.1

Initial release with core authentication, JWT RS256, refresh token rotation, OAuth 2.1 + PKCE (Google, GitHub), RBAC, session management, ban/unban, 15 event types, JWKS, token introspection, multi-database support, FastAPI integration, microservice verifier, and TypeScript client SDK with React/Vue/Svelte integrations.
