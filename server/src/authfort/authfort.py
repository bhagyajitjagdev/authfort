"""AuthFort — instance-based auth configuration and entry point."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

from authfort.config import AuthFortConfig, CookieConfig
from authfort.db import create_engine, create_session_factory, get_session
from authfort.events import (
    EventCollector,
    HookRegistry,
    KeyRotated,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    RoleAdded,
    RoleRemoved,
    SessionRevoked,
    UserBanned,
    UserUnbanned,
    _current_collector,
)

if TYPE_CHECKING:
    from fastapi import APIRouter


class AuthFort:
    """Main AuthFort instance — holds all config and database connection state.

    Args:
        database_url: Required async database URL (e.g. postgresql+asyncpg://...).
        access_token_ttl: Access token lifetime in seconds (default 900 = 15 min).
        refresh_token_ttl: Refresh token lifetime in seconds (default 2592000 = 30 days).
        jwt_issuer: JWT issuer claim (default "authfort").
        jwt_algorithm: JWT algorithm (default "RS256").
        cookie: CookieConfig or None. None = bearer-only, no cookies set.
        providers: List of OAuth providers (e.g. GoogleProvider, GitHubProvider).
        key_rotation_ttl: How long retired signing keys remain valid (seconds, default 48h).
        introspect_secret: Shared secret for introspection endpoint auth (None = open).
        allow_signup: If False, the /auth/signup endpoint returns 403. Programmatic
            create_user() always works regardless of this flag.
        password_reset_ttl: Password reset token lifetime in seconds (default 3600 = 1 hour).
    """

    def __init__(
        self,
        database_url: str,
        *,
        access_token_ttl: int = 900,
        refresh_token_ttl: int = 60 * 60 * 24 * 30,
        jwt_issuer: str = "authfort",
        jwt_algorithm: str = "RS256",
        cookie: CookieConfig | None = None,
        providers: list | None = None,
        key_rotation_ttl: int = 60 * 60 * 48,
        introspect_secret: str | None = None,
        allow_signup: bool = True,
        password_reset_ttl: int = 3600,
    ) -> None:
        self._config = AuthFortConfig(
            database_url=database_url,
            jwt_algorithm=jwt_algorithm,
            access_token_expire_seconds=access_token_ttl,
            refresh_token_expire_seconds=refresh_token_ttl,
            jwt_issuer=jwt_issuer,
            cookie=cookie,
            key_rotation_ttl_seconds=key_rotation_ttl,
            introspect_secret=introspect_secret,
            allow_signup=allow_signup,
            password_reset_ttl_seconds=password_reset_ttl,
        )
        self._engine = create_engine(database_url)
        self._session_factory = create_session_factory(self._engine)
        self._current_user_dep = None
        self._providers = providers or []
        self._hooks = HookRegistry()

    @property
    def config(self) -> AuthFortConfig:
        """Read-only access to the internal config."""
        return self._config

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Access the async session factory (e.g., for testing)."""
        return self._session_factory

    @property
    def hooks(self) -> HookRegistry:
        """Access the hook registry."""
        return self._hooks

    # ------ Event hooks ------

    def on(self, event_name: str):
        """Decorator to register an event hook.

        Usage:
            @auth.on("user_created")
            async def handle(event):
                print(event.email)
        """
        def decorator(fn):
            self._hooks.register(event_name, fn)
            return fn
        return decorator

    def add_hook(self, event_name: str, callback) -> None:
        """Register an event hook callback programmatically."""
        self._hooks.register(event_name, callback)

    # ------ Database session helpers ------

    def get_session(self) -> AsyncGenerator[AsyncSession]:
        """Context manager for service-level code (non-FastAPI)."""
        return get_session(self._session_factory)

    async def _get_db(self) -> AsyncGenerator[AsyncSession]:
        """FastAPI dependency: yields a request-scoped session with event flushing."""
        collector = EventCollector(self._hooks)
        token = _current_collector.set(collector)
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                _current_collector.reset(token)
        # Post-commit: flush collected events
        await collector.flush()

    # ------ Core auth operations ------

    async def create_user(
        self,
        email: str,
        password: str,
        *,
        name: str | None = None,
    ):
        """Create a user programmatically. Always works regardless of allow_signup.

        Returns:
            AuthResponse with user info and tokens.

        Raises:
            AuthError: If email is already registered.
        """
        from authfort.core.auth import signup

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await signup(
                session, config=self._config, email=email,
                password=password, name=name, events=collector,
            )
        await collector.flush()
        return result

    async def login(self, email: str, password: str):
        """Authenticate a user with email and password.

        Returns:
            AuthResponse with user info and tokens.

        Raises:
            AuthError: If credentials are invalid or user is banned.
        """
        from authfort.core.auth import login

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await login(
                session, config=self._config, email=email,
                password=password, events=collector,
            )
        await collector.flush()
        return result

    async def refresh(self, raw_refresh_token: str):
        """Refresh an access token using a refresh token.

        Returns:
            AuthResponse with new tokens (old refresh token is rotated).

        Raises:
            AuthError: If refresh token is invalid, expired, or revoked.
        """
        from authfort.core.auth import refresh

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await refresh(
                session, config=self._config,
                raw_refresh_token=raw_refresh_token, events=collector,
            )
        await collector.flush()
        return result

    async def logout(self, raw_refresh_token: str) -> None:
        """Logout — revoke the refresh token.

        Silently succeeds even if the token is invalid.
        """
        from authfort.core.auth import logout

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await logout(
                session, config=self._config,
                raw_refresh_token=raw_refresh_token, events=collector,
            )
        await collector.flush()

    # ------ Role management ------

    async def add_role(self, user_id: uuid.UUID, role: str, *, immediate: bool = True) -> None:
        """Add a role to a user.

        Args:
            user_id: The user's UUID.
            role: Role string to assign.
            immediate: If True (default), bumps token_version so existing tokens
                are invalidated and the user must re-login/refresh. If False, the
                role takes effect on next login/refresh (lazy).
        """
        from authfort.repositories import role as role_repo
        from authfort.repositories import user as user_repo

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await role_repo.add_role(session, user_id, role)
            if immediate:
                await user_repo.bump_token_version(session, user_id)
            collector.collect("role_added", RoleAdded(user_id=user_id, role=role))
        await collector.flush()

    async def remove_role(self, user_id: uuid.UUID, role: str, *, immediate: bool = True) -> None:
        """Remove a role from a user.

        Args:
            user_id: The user's UUID.
            role: Role string to remove.
            immediate: If True (default), bumps token_version so existing tokens
                are invalidated. If False, the role removal takes effect on next
                login/refresh (lazy).
        """
        from authfort.repositories import role as role_repo
        from authfort.repositories import user as user_repo

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await role_repo.remove_role(session, user_id, role)
            if immediate:
                await user_repo.bump_token_version(session, user_id)
            collector.collect("role_removed", RoleRemoved(user_id=user_id, role=role))
        await collector.flush()

    async def get_roles(self, user_id: uuid.UUID) -> list[str]:
        """Get all roles for a user."""
        from authfort.repositories import role as role_repo

        async with get_session(self._session_factory) as session:
            return await role_repo.get_roles(session, user_id)

    # ------ Password management ------

    async def create_password_reset_token(self, email: str) -> str | None:
        """Create a password reset token for a user.

        Returns the raw token string if the user exists and has a password,
        or None if not found / OAuth-only (prevents user enumeration).
        The caller handles delivery (email, SMS, etc.).
        """
        from authfort.core.auth import create_password_reset_token

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await create_password_reset_token(
                session, config=self._config, email=email, events=collector,
            )
        await collector.flush()
        return result

    async def reset_password(self, token: str, new_password: str) -> bool:
        """Reset a user's password using a reset token.

        Validates the token, updates the password, and bumps token_version
        (invalidating all existing JWTs).

        Returns:
            True on success.

        Raises:
            AuthError: If the token is invalid or expired.
        """
        from authfort.core.auth import reset_password

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await reset_password(
                session, config=self._config, token=token,
                new_password=new_password, events=collector,
            )
        await collector.flush()
        return result

    async def change_password(
        self, user_id: uuid.UUID, old_password: str, new_password: str,
    ) -> None:
        """Change a user's password (requires the old password).

        Verifies the old password, hashes the new one, and bumps token_version
        to force re-login everywhere.

        Raises:
            AuthError: If user not found, OAuth-only, or wrong old password.
        """
        from authfort.core.auth import change_password

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await change_password(
                session, user_id=user_id, old_password=old_password,
                new_password=new_password, events=collector,
            )
        await collector.flush()

    # ------ User management ------

    async def ban_user(self, user_id: uuid.UUID) -> None:
        """Ban a user — immediately invalidates all tokens and sessions.

        Sets banned=True, bumps token_version, revokes all refresh tokens.
        The user cannot login, refresh, or access protected routes until unbanned.
        """
        from authfort.repositories import user as user_repo

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await user_repo.ban_user(session, user_id)
            collector.collect("user_banned", UserBanned(user_id=user_id))
        await collector.flush()

    async def unban_user(self, user_id: uuid.UUID) -> None:
        """Unban a user — allows them to login again."""
        from authfort.repositories import user as user_repo

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await user_repo.unban_user(session, user_id)
            collector.collect("user_unbanned", UserUnbanned(user_id=user_id))
        await collector.flush()

    # ------ Session management ------

    async def get_sessions(
        self, user_id: uuid.UUID, *, active_only: bool = False,
    ) -> list:
        """List sessions for a user.

        Args:
            user_id: The user's UUID.
            active_only: If True, only return active (non-revoked, non-expired) sessions.

        Returns:
            List of SessionResponse objects, newest first.
        """
        from authfort.core.sessions import get_sessions

        async with get_session(self._session_factory) as session:
            return await get_sessions(session, user_id, active_only=active_only)

    async def revoke_session(self, session_id: uuid.UUID) -> bool:
        """Revoke a specific session by its ID.

        Returns True if the session was found and revoked, False otherwise.
        """
        from authfort.core.sessions import revoke_session

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            result = await revoke_session(session, session_id)
            if result:
                collector.collect("session_revoked", SessionRevoked(session_id=session_id))
        await collector.flush()
        return result

    async def revoke_all_sessions(
        self, user_id: uuid.UUID, *, exclude: uuid.UUID | None = None,
    ) -> None:
        """Revoke ALL sessions for a user (logs them out everywhere).

        Args:
            user_id: The user's UUID.
            exclude: If provided, keep this session alive (e.g. the current session).
        """
        from authfort.core.sessions import revoke_all_sessions

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            await revoke_all_sessions(session, user_id, exclude=exclude)
            collector.collect("session_revoked", SessionRevoked(user_id=user_id, revoke_all=True))
        await collector.flush()

    # ------ Key rotation ------

    async def rotate_key(self) -> str:
        """Rotate the signing key — create a new key pair, retire the old one.

        The old key gets expires_at set to now + key_rotation_ttl, so it remains
        valid for JWT verification until then.

        Returns:
            The kid of the new signing key.
        """
        from datetime import UTC, datetime, timedelta

        from authfort.core.keys import generate_key_pair, generate_kid
        from authfort.repositories import signing_key as signing_key_repo

        collector = EventCollector(self._hooks)
        async with get_session(self._session_factory) as session:
            old_key = await signing_key_repo.get_current_signing_key(session)
            old_kid = old_key.kid if old_key else ""

            if old_key is not None:
                expires_at = datetime.now(UTC) + timedelta(
                    seconds=self._config.key_rotation_ttl_seconds,
                )
                await signing_key_repo.set_expires_at(session, old_key.id, expires_at)

            private_pem, public_pem = generate_key_pair()
            kid = generate_kid()
            await signing_key_repo.create_signing_key(
                session,
                kid=kid,
                private_key=private_pem,
                public_key=public_pem,
                algorithm=self._config.jwt_algorithm,
                is_current=True,
            )

            collector.collect("key_rotated", KeyRotated(old_kid=old_kid, new_kid=kid))
        await collector.flush()
        return kid

    async def cleanup_expired_keys(self) -> int:
        """Delete signing keys whose expires_at has passed.

        Returns:
            Number of keys deleted.
        """
        from authfort.repositories import signing_key as signing_key_repo

        async with get_session(self._session_factory) as session:
            return await signing_key_repo.delete_expired_keys(session)

    # ------ FastAPI integration ------

    def fastapi_router(self) -> APIRouter:
        """Create a FastAPI router with all auth endpoints, bound to this instance.

        Includes: signup, login, refresh, logout, me, introspect.
        With OAuth providers: oauth authorize/callback endpoints.

        Note: Mount this under a prefix (e.g. /auth). For the JWKS endpoint,
        use jwks_router() separately at the root level.
        """
        from authfort.integrations.fastapi.introspect_router import create_introspect_router
        from authfort.integrations.fastapi.router import create_auth_router

        router = create_auth_router(self._config, self._get_db, self._hooks)

        if self._providers:
            from authfort.integrations.fastapi.oauth_router import create_oauth_router

            oauth_router = create_oauth_router(
                self._config, self._get_db, self._providers, self._hooks,
            )
            router.include_router(oauth_router)

        introspect_router = create_introspect_router(self._config, self._get_db)
        router.include_router(introspect_router)

        return router

    def jwks_router(self) -> APIRouter:
        """Create a FastAPI router for the JWKS endpoint.

        Mount this at the root (no prefix) so the endpoint is at /.well-known/jwks.json.

        Usage:
            app.include_router(auth.fastapi_router(), prefix="/auth")
            app.include_router(auth.jwks_router())  # root level
        """
        from authfort.integrations.fastapi.jwks_router import create_jwks_router

        return create_jwks_router(self._config, self._get_db)

    @property
    def current_user(self):
        """FastAPI dependency: get the current authenticated user.

        Usage:
            @app.get("/profile")
            async def profile(user=Depends(auth.current_user)):
                ...
        """
        if self._current_user_dep is None:
            from authfort.integrations.fastapi.deps import create_current_user_dep

            self._current_user_dep = create_current_user_dep(self._config, self._get_db)
        return self._current_user_dep

    def require_role(self, role: str | list[str]):
        """FastAPI dependency factory: require a specific role.

        Usage:
            @app.get("/admin")
            async def admin(user=Depends(auth.require_role("admin"))):
                ...
        """
        from authfort.integrations.fastapi.deps import create_require_role_dep

        return create_require_role_dep(self._config, self._get_db, role)

    # ------ Migrations ------

    async def migrate(self) -> None:
        """Run pending database migrations. Safe to call on every startup.

        Uses bundled Alembic migrations to create or update the schema.
        Tracks state in the ``authfort_alembic_version`` table (separate
        from any developer Alembic setup).
        """
        from pathlib import Path

        from alembic import command
        from alembic.config import Config

        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(__file__).parent / "migrations"),
        )

        async with self._engine.begin() as conn:
            await conn.run_sync(self._run_upgrade, config)

    @staticmethod
    def _run_upgrade(connection, config) -> None:
        from alembic import command

        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    # ------ Lifecycle ------

    async def dispose(self) -> None:
        """Dispose the database engine (for clean shutdown)."""
        await self._engine.dispose()
