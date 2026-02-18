"""AuthFort configuration — dataclasses for cookie and auth settings."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class CookieConfig:
    """Configuration for auth cookies. Pass to AuthFort to enable cookie delivery."""

    secure: bool = True
    httponly: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"
    path: str = "/"
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"


@dataclass(frozen=True, slots=True)
class AuthFortConfig:
    """Internal config built by the AuthFort constructor. Not user-facing."""

    database_url: str
    jwt_algorithm: str = "RS256"
    access_token_expire_seconds: int = 900
    refresh_token_expire_seconds: int = 60 * 60 * 24 * 30  # 30 days
    jwt_issuer: str = "authfort"
    cookie: CookieConfig | None = None
    key_rotation_ttl_seconds: int = 60 * 60 * 48  # 48 hours
    introspect_secret: str | None = None
    allow_signup: bool = True
