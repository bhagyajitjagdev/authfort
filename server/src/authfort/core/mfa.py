"""TOTP MFA core logic — secret generation, code verification, backup codes, challenge tokens."""

import hashlib
import math
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pyotp

from authfort.config import JWT_ALGORITHM, AuthFortConfig

MFA_CHALLENGE_PURPOSE = "mfa_challenge"
MFA_CHALLENGE_TTL_SECONDS = 300  # 5 minutes

_BACKUP_CODE_ALPHABET = string.ascii_lowercase + string.digits


# ---------------------------------------------------------------------------
# TOTP secret
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Generate a random base32 TOTP secret suitable for Google Authenticator."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str) -> str:
    """Return the otpauth:// URI for QR code generation.

    The caller is responsible for encoding this into a QR image.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


# ---------------------------------------------------------------------------
# TOTP verification (with replay protection)
# ---------------------------------------------------------------------------


def verify_totp_code(
    secret: str,
    code: str,
    *,
    last_used_at: datetime | None,
    last_used_code: str | None,
) -> bool:
    """Verify a 6-digit TOTP code.

    Allows ±1 time window (90 s grace) to handle clock drift.
    Rejects codes that match the last accepted code within the same 30 s window
    (replay protection).

    Args:
        secret: Base32 TOTP secret for the user.
        code: 6-digit code submitted by the user.
        last_used_at: Timestamp of the last accepted code, for replay detection.
        last_used_code: The last accepted code value.

    Returns:
        True if the code is valid and not a replay.
    """
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return False

    # Replay protection: reject if same code was used in the current 30 s window
    if last_used_code == code and last_used_at is not None:
        now = datetime.now(UTC)
        current_window = math.floor(now.timestamp() / 30)
        last_window = math.floor(last_used_at.timestamp() / 30)
        if current_window == last_window:
            return False

    return True


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate plaintext backup codes.

    Format: xxxxx-xxxxx (5 random alphanumeric chars, hyphen, 5 more).
    Shown to the user exactly once — never stored in plaintext.
    """
    codes = []
    for _ in range(count):
        part1 = "".join(secrets.choice(_BACKUP_CODE_ALPHABET) for _ in range(5))
        part2 = "".join(secrets.choice(_BACKUP_CODE_ALPHABET) for _ in range(5))
        codes.append(f"{part1}-{part2}")
    return codes


def hash_backup_code(code: str) -> str:
    """SHA-256 hex digest of a backup code (normalised to lowercase, no spaces)."""
    normalised = code.lower().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalised.encode()).hexdigest()


def verify_backup_code(code: str, code_hashes: list[str]) -> str | None:
    """Check whether a submitted backup code matches any stored hash.

    Args:
        code: The plaintext code submitted by the user.
        code_hashes: List of SHA-256 hashes of unused backup codes.

    Returns:
        The matching hash string if found, None otherwise.
    """
    submitted_hash = hash_backup_code(code)
    for stored_hash in code_hashes:
        if secrets.compare_digest(submitted_hash, stored_hash):
            return stored_hash
    return None


# ---------------------------------------------------------------------------
# MFA challenge token (short-lived JWT for the login second step)
# ---------------------------------------------------------------------------


def create_mfa_challenge_token(
    user_id: uuid.UUID,
    private_key: str,
    kid: str,
    config: AuthFortConfig,
) -> str:
    """Create a short-lived signed JWT to represent a pending MFA challenge.

    Issued after password verification succeeds. The client presents this token
    alongside the TOTP code to complete the login.

    The token carries:
      - ``sub``: user UUID
      - ``purpose``: "mfa_challenge" (guards against misuse as an access token)
      - ``exp``: 5 minutes from now
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "purpose": MFA_CHALLENGE_PURPOSE,
        "iat": now,
        "exp": now + timedelta(seconds=MFA_CHALLENGE_TTL_SECONDS),
        "iss": config.jwt_issuer,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm=JWT_ALGORITHM,
        headers={"kid": kid},
    )


def verify_mfa_challenge_token(
    token: str,
    public_key: str,
    config: AuthFortConfig,
) -> uuid.UUID:
    """Verify an MFA challenge token and return the user_id.

    Args:
        token: The encoded challenge JWT.
        public_key: PEM public key matching the kid in the token header.
        config: AuthFort configuration.

    Returns:
        The user UUID from the ``sub`` claim.

    Raises:
        jwt.ExpiredSignatureError: Token has expired (> 5 minutes since login).
        jwt.InvalidTokenError: Token is malformed, wrong issuer, or wrong purpose.
    """
    payload = jwt.decode(
        token,
        public_key,
        algorithms=[JWT_ALGORITHM],
        issuer=config.jwt_issuer,
        options={"require": ["sub", "purpose", "exp", "iat", "iss"]},
    )
    if payload.get("purpose") != MFA_CHALLENGE_PURPOSE:
        raise jwt.InvalidTokenError("Token is not an MFA challenge token")
    return uuid.UUID(payload["sub"])
