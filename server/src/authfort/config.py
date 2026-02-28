"""AuthFort configuration — dataclasses for cookie, rate limit, and auth settings."""

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import Literal

JWT_ALGORITHM = "RS256"


@dataclass(frozen=True, slots=True)
class CookieConfig:
    """Configuration for auth cookies. Pass to AuthFort to enable cookie delivery."""

    secure: bool = True
    httponly: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"
    path: str = "/"
    domain: str | None = None
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Per-endpoint rate limits. Pass to AuthFort to enable rate limiting.

    Format: "{count}/{period}" where period is sec/min/hour/day.
    Set an individual field to None to skip rate limiting for that endpoint.

    Example:
        RateLimitConfig()                       # All defaults
        RateLimitConfig(login="10/min")         # Override login only
        RateLimitConfig(signup=None)            # Disable signup limiting
    """

    login: str | None = "5/min"
    signup: str | None = "3/min"
    magic_link: str | None = "5/min"
    otp: str | None = "5/min"
    verify_email: str | None = "5/min"
    refresh: str | None = "30/min"
    oauth_authorize: str | None = "10/min"

    def __post_init__(self) -> None:
        """Validate all rate limit strings at construction time."""
        from authfort.ratelimit import parse_rate_limit

        for field_name in (
            "login", "signup", "magic_link", "otp", "verify_email",
            "refresh", "oauth_authorize",
        ):
            value = getattr(self, field_name)
            if value is not None:
                parse_rate_limit(value)


@dataclass(frozen=True, slots=True)
class AuthFortConfig:
    """Internal config built by the AuthFort constructor. Not user-facing."""

    database_url: str
    access_token_expire_seconds: int = 900
    refresh_token_expire_seconds: int = 60 * 60 * 24 * 30  # 30 days
    jwt_issuer: str = "authfort"
    cookie: CookieConfig | None = None
    key_rotation_ttl_seconds: int = 60 * 60 * 48  # 48 hours
    introspect_secret: str | None = None
    allow_signup: bool = True
    password_reset_ttl_seconds: int = 3600  # 1 hour
    rsa_key_size: int = 2048
    frontend_url: str | None = None
    email_verify_ttl_seconds: int = 86400  # 24 hours
    magic_link_ttl_seconds: int = 600  # 10 minutes
    email_otp_ttl_seconds: int = 300  # 5 minutes
    allow_passwordless_signup: bool = False
    rate_limit: RateLimitConfig | None = None
    trust_proxy: bool = False
    trusted_proxy_networks: tuple[IPv4Network | IPv6Network, ...] = ()
