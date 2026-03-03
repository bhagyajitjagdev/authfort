---
title: Changelog
description: Version history and breaking changes.
sidebar:
  order: 1
---

All notable changes to AuthFort are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
