"""Input validation and sanitization for user-facing fields.

Defends against XSS, SQL injection payloads, email header injection,
and other malicious input that VAPT scanners flag.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import nh3
from email_validator import EmailNotValidError, validate_email

from authfort.core.errors import AuthError

# Control characters (C0/C1) minus tab, newline, carriage return
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Max field lengths (should match DB column sizes)
_MAX_EMAIL_LENGTH = 255
_MAX_NAME_LENGTH = 255
_MAX_PHONE_LENGTH = 50
_MAX_AVATAR_URL_LENGTH = 2048


def validate_user_email(email: str) -> str:
    """Validate and normalize an email address.

    Uses the email-validator library for RFC-compliant validation.
    Returns the normalized email (lowered, stripped).

    Raises:
        AuthError: If the email is invalid (code: invalid_email).
    """
    if not email or not isinstance(email, str):
        raise AuthError("Invalid email address", code="invalid_email", status_code=400)

    email = email.strip()

    if len(email) > _MAX_EMAIL_LENGTH:
        raise AuthError("Email address is too long", code="invalid_email", status_code=400)

    try:
        result = validate_email(email, check_deliverability=False)
        return result.normalized.lower()
    except EmailNotValidError:
        raise AuthError("Invalid email address", code="invalid_email", status_code=400)


def sanitize_name(name: str | None) -> str | None:
    """Sanitize a display name — strip all HTML tags and control characters.

    Returns:
        Cleaned name string, or None if the result is empty/whitespace.

    Raises:
        AuthError: If the name exceeds max length after sanitization.
    """
    if name is None:
        return None

    if not isinstance(name, str):
        raise AuthError("Invalid name", code="invalid_name", status_code=400)

    # Strip all HTML tags
    cleaned = nh3.clean(name, tags=set())
    # Remove control characters
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    # Normalize whitespace
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.strip()

    if not cleaned:
        return None

    if len(cleaned) > _MAX_NAME_LENGTH:
        raise AuthError(
            f"Name must be {_MAX_NAME_LENGTH} characters or fewer",
            code="invalid_name",
            status_code=400,
        )

    return cleaned


def sanitize_phone(phone: str | None) -> str | None:
    """Sanitize a phone number — strip HTML, control chars, and validate format.

    Returns:
        Cleaned phone string, or None if empty.

    Raises:
        AuthError: If the phone contains invalid characters or exceeds max length.
    """
    if phone is None:
        return None

    if not isinstance(phone, str):
        raise AuthError("Invalid phone number", code="invalid_phone", status_code=400)

    # Strip all HTML tags
    cleaned = nh3.clean(phone, tags=set())
    # Remove control characters
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    cleaned = cleaned.strip()

    if not cleaned:
        return None

    # Phone numbers should only contain digits, spaces, dashes, parens, dots, and +
    if not re.match(r"^[0-9\s\-\(\)\.\+]+$", cleaned):
        raise AuthError(
            "Phone number contains invalid characters",
            code="invalid_phone",
            status_code=400,
        )

    if len(cleaned) > _MAX_PHONE_LENGTH:
        raise AuthError(
            f"Phone number must be {_MAX_PHONE_LENGTH} characters or fewer",
            code="invalid_phone",
            status_code=400,
        )

    return cleaned


def validate_avatar_url(avatar_url: str | None) -> str | None:
    """Validate an avatar URL — must be http or https.

    Returns:
        The URL string, or None if empty.

    Raises:
        AuthError: If the URL is not a valid http/https URL.
    """
    if avatar_url is None:
        return None

    if not isinstance(avatar_url, str):
        raise AuthError("Invalid avatar URL", code="invalid_avatar_url", status_code=400)

    avatar_url = avatar_url.strip()

    if not avatar_url:
        return None

    if len(avatar_url) > _MAX_AVATAR_URL_LENGTH:
        raise AuthError(
            "Avatar URL is too long",
            code="invalid_avatar_url",
            status_code=400,
        )

    try:
        parsed = urlparse(avatar_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise AuthError(
                "Avatar URL must be a valid http or https URL",
                code="invalid_avatar_url",
                status_code=400,
            )
    except ValueError:
        raise AuthError(
            "Avatar URL must be a valid http or https URL",
            code="invalid_avatar_url",
            status_code=400,
        )

    return avatar_url


def validate_password(password: str, *, min_length: int = 8) -> str:
    """Validate password meets minimum length requirement.

    Raises:
        AuthError: If password is too short (code: password_too_short).
    """
    if not password or not isinstance(password, str):
        raise AuthError(
            f"Password must be at least {min_length} characters",
            code="password_too_short",
            status_code=400,
        )

    if len(password) < min_length:
        raise AuthError(
            f"Password must be at least {min_length} characters",
            code="password_too_short",
            status_code=400,
        )

    return password
