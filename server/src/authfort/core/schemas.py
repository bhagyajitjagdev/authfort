"""Auth service schemas — request/response models for the core auth logic."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class AuthTokens(BaseModel):
    """Token pair returned after login/signup/refresh."""
    access_token: str
    refresh_token: str
    expires_in: int


class AuthResponse(BaseModel):
    """Full auth response with user data and tokens."""
    user: "UserResponse"
    tokens: AuthTokens


class MFAChallenge(BaseModel):
    """Returned by login() when the user has MFA enabled.

    The client must present ``mfa_token`` + a TOTP code to ``/auth/mfa/verify``
    to complete the login and receive full tokens.
    """
    mfa_required: bool = True
    mfa_token: str
    expires_in: int = 300


class MFASetup(BaseModel):
    """Returned by enable_mfa_init — contains the TOTP secret and QR URI.

    The caller encodes ``qr_uri`` into a QR image for the user to scan.
    ``secret`` is shown as a fallback for manual entry.
    """
    secret: str
    qr_uri: str


class MFAStatus(BaseModel):
    """Current MFA state for a user."""
    enabled: bool
    backup_codes_remaining: int


class UserResponse(BaseModel):
    """User data returned in API responses (no password hash)."""
    id: uuid.UUID
    email: str
    name: str | None
    email_verified: bool
    avatar_url: str | None
    phone: str | None = None
    banned: bool = False
    roles: list[str]
    created_at: datetime
    session_id: uuid.UUID | None = None
    mfa_enabled: bool = False


class ListUsersResponse(BaseModel):
    """Paginated list of users."""
    users: list[UserResponse]
    total: int
    limit: int
    offset: int


class SessionResponse(BaseModel):
    """A user session (refresh token) for session management UIs."""
    id: uuid.UUID
    user_agent: str | None
    ip_address: str | None
    created_at: datetime
    expires_at: datetime
    revoked: bool


class SignupRequest(BaseModel):
    """Email/password signup input."""
    email: str
    password: str
    name: str | None = None
    avatar_url: str | None = None
    phone: str | None = None


class LoginRequest(BaseModel):
    """Email/password login input."""
    email: str
    password: str


class RefreshRequest(BaseModel):
    """Refresh token input."""
    refresh_token: str | None = None


class MagicLinkRequest(BaseModel):
    """Magic link request input."""
    email: str


class MagicLinkVerifyRequest(BaseModel):
    """Magic link verification input."""
    token: str


class OTPRequest(BaseModel):
    """Email OTP request input."""
    email: str


class OTPVerifyRequest(BaseModel):
    """Email OTP verification input."""
    email: str
    code: str


class EmailVerifyRequest(BaseModel):
    """Email verification input."""
    token: str


class SetPasswordRequest(BaseModel):
    """Set initial password for passwordless users."""
    password: str


class MFAVerifyRequest(BaseModel):
    """Second login step — submit the MFA challenge token + TOTP or backup code."""
    mfa_token: str
    code: str


class MFAConfirmRequest(BaseModel):
    """Confirm MFA setup by verifying the first TOTP code."""
    code: str


class MFADisableRequest(BaseModel):
    """Disable MFA — requires a TOTP code or backup code for verification."""
    code: str


class MFARegenerateBackupCodesRequest(BaseModel):
    """Regenerate backup codes — requires current TOTP code for verification."""
    code: str


# Rebuild forward refs
AuthResponse.model_rebuild()
