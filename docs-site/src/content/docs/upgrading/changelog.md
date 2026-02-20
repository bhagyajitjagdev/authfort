---
title: Changelog
description: Version history and breaking changes.
sidebar:
  order: 1
---

All notable changes to AuthFort are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
