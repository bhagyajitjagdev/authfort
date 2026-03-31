# AuthFort — Status

## Resume Point

- **Date**: 2026-03-31
- **Current Version**: v0.0.20 (ready for tag + publish)
- **Current State**: Input validation and sanitization — VAPT security fix
- **Next Step**: Tag v0.0.20 and publish to PyPI/npm

## Latest Session (2026-03-31)

### Input validation and sanitization (VAPT security fix)

- **VAPT finding**: User's app was tested by a VAPT company — they stored XSS (`<svg onload=alert(1)>`), SQL injection, XXE, and email header injection payloads in name/email fields
- **Root cause**: No input validation on signup/create_user — loose email regex, zero name/phone sanitization
- **Added `email-validator` library**: RFC-compliant email validation replaces the old loose regex — rejects all injection payloads
- **Added `nh3` library**: Rust-based HTML sanitizer strips all tags from name/phone fields — prevents stored XSS
- **Avatar URL validation**: Only `http://` and `https://` URLs accepted (rejects `javascript:`, `data:`, etc.)
- **Password min length**: Configurable via `min_password_length` (default 8) — enforced on signup, change_password, set_password, reset_password
- **`AuthError` moved to `authfort.core.errors`** to break circular import (re-exported from `auth.py` — no breaking changes)
- **Validation wired into all entry points**: signup, login, OAuth, magic link, OTP, update_user, change_password, set_password, reset_password
- 60 new validation tests, 541 total, all passing
- New dependencies: `email-validator>=2.3.0`, `nh3>=0.3.4`

## Previous Session (2026-03-12)

### Passwordless user flow fixes (ticket from external review)

- **Fixed wrong "social login" error for passwordless users**: `login()` and `change_password()` now distinguish OAuth users (code: `oauth_account`) from passwordless users (code: `no_password`) by checking account records
- **Added `set_password(user_id, new_password)`**: New core method + `AuthFort.set_password()` + `POST /auth/set-password` endpoint for passwordless users to add a password
- **Forgot-password now works for all users**: `create_password_reset_token()` no longer skips users with `password_hash=None` — passwordless/OAuth users can use forgot-password to set their initial password
- **`reset_password()` creates email account record**: When a passwordless user sets their first password via reset, an `email` account is created automatically
- **Banned check moved after password verification**: In `login()`, prevents banned-account probing without knowing the password
- **New `PasswordSet` event**: Fires when a passwordless user sets their initial password
- Updated docs: password-management.mdx, server-api.mdx, server-events.mdx, magic-links.mdx, otp.mdx
- Tests updated: 3 new test cases in test_password.py, all 480+ tests passing

## Previous Session (2026-03-03)

### email_verified on create_user / update_user

- `auth.create_user(..., email_verified=True)` — admin-created accounts skip email verification
- `auth.update_user(user_id, email_verified=True)` — admin can manually verify/unverify a user
- `EmailVerified` event fires on `True` (create) or `False→True` transition (update), no duplicate events
- Regular signup endpoint untouched — always `email_verified=False`
- 11 new tests (491 server total), all passing
- Docs updated: server-api.mdx, authentication.mdx, server-events.mdx, changelog

### Security audit (review only, no code changes)

- Full endpoint audit for information leakage — no stack traces, no DB internals, no credential leaks
- One item flagged for future fix: OAuth callback leaks raw exception messages (`"Failed to exchange OAuth code: {e}"`)
- Signup `user_exists`, login `oauth_account`/`user_banned` are intentional UX trade-offs protected by rate limiting
- Magic link, OTP, introspection, logout are all excellent (generic responses, no enumeration)

### Previous Session (2026-02-28)

- v0.0.17: trust_proxy/trusted_proxies, stable session_id, cookie refresh dedup
- v0.0.16: change_password 400 fix, OAuth-only login 400 fix
- v0.0.15: CLI migrate command, register_foreign_tables, alembic_filters
- v0.0.14: Boolean default fix for PostgreSQL
- v0.0.13: AuthUser/AuthUserRole exports
- v0.0.12: banned field on UserResponse
- v0.0.11: Rate limiting + admin user management

### Earlier Sessions

- v0.0.10 — Email verify, magic links, OTP, generic OAuth/OIDC
- v0.0.9 — Cleanup APIs, user profile, OAuth enhancements, docs site
- v0.0.8 — SQLModel → SQLAlchemy migration
- v0.0.7 — Security audit fixes
- v0.0.6 — DB isolation, cookie domain, service cookie support
- v0.0.5 — Bearer mode TokenStorage
- v0.0.4 — Password reset, change password
- v0.0.3 — CI/CD live, first published release

## Overall Phase Status

| Phase | Name                          | Status       | Details            |
| ----- | ----------------------------- | ------------ | ------------------ |
| 1     | Core (MVP)                    | Done v0.0.1  | `docs/phase1.md`   |
| 2     | Roles, OAuth, Sessions, Events| Done v0.0.1  | `docs/phase2.md`   |
| 3     | Microservices                 | Done v0.0.1  | `docs/phase3.md`   |
| 4     | Client SDK, DB Adapters, Hooks| Done v0.0.1  | `docs/phase4.md`   |
| 5     | Password Management           | Done v0.0.4  | `docs/phase5.md`   |
| 6     | DB Isolation, Cookies         | Done v0.0.6  | `docs/phase6.md`   |
| 7     | Security Audit Fixes          | Done v0.0.7  | `docs/phase7.md`   |
| 8     | SQLModel → SQLAlchemy         | Done v0.0.8  | `docs/phase8.md`   |
| 9     | Cleanup & Maintenance APIs    | Done v0.0.9  | `docs/phase9.md`   |
| 10    | Documentation Website         | Done v0.0.9  | `docs/phase10.md`  |
| 11    | Email Verify, Magic Links, OTP, Generic OAuth | Done v0.0.10 | `docs/phase11.md` |
| —     | Plugin System                 | Discussion   | `docs/maybe/plugin-system.md` |
| —     | React Native OAuth            | Discussion   | `docs/maybe/rn-oauth.md`      |

## Tech Debt

- OAuth callback leaks raw exception messages — should log internally and return generic error (flagged in 2026-03-03 security audit)
