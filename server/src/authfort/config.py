"""AuthFort configuration — dataclasses for cookie and auth settings."""

from dataclasses import dataclass
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
