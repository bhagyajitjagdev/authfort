"""AuthFort event system — typed events, hook registry, and event collection.

Developers register hooks via @auth.on("event_name") to react to auth events
(send emails, audit logs, sync external systems). Hooks run after DB commit
and are fail-open (errors logged, never break the auth flow).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable

logger = logging.getLogger("authfort.events")


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Event:
    """Base event — all events carry a timestamp."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class UserCreated(Event):
    """Fired when a new user is created (signup or first OAuth login)."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    name: str | None = None
    provider: str = "email"


@dataclass(frozen=True, slots=True)
class Login(Event):
    """Fired on successful login (email/password or OAuth)."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    provider: str = "email"
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class LoginFailed(Event):
    """Fired when login fails (wrong password, banned, etc.)."""
    email: str = ""
    reason: str = ""
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class OAuthLink(Event):
    """Fired when a new OAuth provider is linked to an existing user."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    provider: str = ""


@dataclass(frozen=True, slots=True)
class UserBanned(Event):
    """Fired when a user is banned."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass(frozen=True, slots=True)
class UserUnbanned(Event):
    """Fired when a user is unbanned."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass(frozen=True, slots=True)
class RoleAdded(Event):
    """Fired when a role is assigned to a user."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    role: str = ""


@dataclass(frozen=True, slots=True)
class RoleRemoved(Event):
    """Fired when a role is removed from a user."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    role: str = ""


@dataclass(frozen=True, slots=True)
class SessionRevoked(Event):
    """Fired when sessions are revoked (single or all)."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    session_id: uuid.UUID | None = None
    revoke_all: bool = False


@dataclass(frozen=True, slots=True)
class TokenRefreshed(Event):
    """Fired on successful token refresh."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class Logout(Event):
    """Fired when a user logs out."""
    user_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class KeyRotated(Event):
    """Fired when signing keys are rotated."""
    old_kid: str = ""
    new_kid: str = ""


@dataclass(frozen=True, slots=True)
class PasswordResetRequested(Event):
    """Fired when a password reset token is created."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""


@dataclass(frozen=True, slots=True)
class PasswordReset(Event):
    """Fired when a password is successfully reset via token."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass(frozen=True, slots=True)
class PasswordChanged(Event):
    """Fired when a user changes their password (old password verified)."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass(frozen=True, slots=True)
class UserUpdated(Event):
    """Fired when a user's profile fields are updated."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    fields: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EmailVerificationRequested(Event):
    """Fired when an email verification token is created."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    token: str = ""


@dataclass(frozen=True, slots=True)
class EmailVerified(Event):
    """Fired when a user's email is successfully verified."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""


@dataclass(frozen=True, slots=True)
class MagicLinkRequested(Event):
    """Fired when a magic link token is created."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    token: str = ""


@dataclass(frozen=True, slots=True)
class MagicLinkLogin(Event):
    """Fired when a user logs in via magic link."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""


@dataclass(frozen=True, slots=True)
class EmailOTPRequested(Event):
    """Fired when an email OTP code is created."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""
    code: str = ""


@dataclass(frozen=True, slots=True)
class EmailOTPLogin(Event):
    """Fired when a user logs in via email OTP."""
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    email: str = ""


# ---------------------------------------------------------------------------
# Event name mapping
# ---------------------------------------------------------------------------

EVENT_MAP: dict[str, type[Event]] = {
    "user_created": UserCreated,
    "login": Login,
    "login_failed": LoginFailed,
    "oauth_link": OAuthLink,
    "user_banned": UserBanned,
    "user_unbanned": UserUnbanned,
    "role_added": RoleAdded,
    "role_removed": RoleRemoved,
    "session_revoked": SessionRevoked,
    "token_refreshed": TokenRefreshed,
    "logout": Logout,
    "key_rotated": KeyRotated,
    "password_reset_requested": PasswordResetRequested,
    "password_reset": PasswordReset,
    "password_changed": PasswordChanged,
    "user_updated": UserUpdated,
    "email_verification_requested": EmailVerificationRequested,
    "email_verified": EmailVerified,
    "magic_link_requested": MagicLinkRequested,
    "magic_link_login": MagicLinkLogin,
    "email_otp_requested": EmailOTPRequested,
    "email_otp_login": EmailOTPLogin,
}


# ---------------------------------------------------------------------------
# Hook registry
# ---------------------------------------------------------------------------

HookCallback = Callable[..., Any]


class HookRegistry:
    """Registry for event hook callbacks. Supports multiple listeners per event."""

    def __init__(self) -> None:
        self._hooks: dict[str, list[HookCallback]] = {}

    def register(self, event_name: str, callback: HookCallback) -> None:
        """Register a callback for an event name."""
        if event_name not in EVENT_MAP:
            raise ValueError(
                f"Unknown event '{event_name}'. "
                f"Valid events: {', '.join(sorted(EVENT_MAP))}"
            )
        self._hooks.setdefault(event_name, []).append(callback)

    def get_hooks(self, event_name: str) -> list[HookCallback]:
        """Get all registered callbacks for an event name."""
        return self._hooks.get(event_name, [])

    async def emit(self, event_name: str, event: Event) -> None:
        """Fire all registered callbacks for an event. Fail-open: errors are logged."""
        for callback in self.get_hooks(event_name):
            try:
                if inspect.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, callback, event)
            except Exception:
                logger.exception(
                    "Hook error in '%s' handler %s.%s",
                    event_name,
                    callback.__module__,
                    callback.__qualname__,
                )


# ---------------------------------------------------------------------------
# Event collector
# ---------------------------------------------------------------------------

class EventCollector:
    """Collects events during a transaction, emits them after commit."""

    def __init__(self, registry: HookRegistry) -> None:
        self._registry = registry
        self._pending: list[tuple[str, Event]] = []

    def collect(self, event_name: str, event: Event) -> None:
        """Add an event to the pending list (called inside transaction)."""
        self._pending.append((event_name, event))

    async def flush(self) -> None:
        """Emit all pending events (called after commit). Clears the list."""
        events = self._pending.copy()
        self._pending.clear()
        for event_name, event in events:
            await self._registry.emit(event_name, event)


# ---------------------------------------------------------------------------
# ContextVar for request-scoped collector (used by FastAPI integration)
# ---------------------------------------------------------------------------

_current_collector: ContextVar[EventCollector | None] = ContextVar(
    "_current_collector", default=None,
)


def get_collector() -> EventCollector | None:
    """Get the current request's event collector (if any)."""
    return _current_collector.get()
