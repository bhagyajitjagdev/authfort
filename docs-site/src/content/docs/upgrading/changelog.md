---
title: Changelog
description: Version history and breaking changes.
sidebar:
  order: 1
---

All notable changes to AuthFort are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
