"""Input validation and sanitization for user-facing fields.

Defends against XSS, SQL injection payloads, email header injection,
and other malicious input that VAPT scanners flag.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from urllib.parse import urlparse

import httpx
import nh3
from email_validator import EmailNotValidError, validate_email

from authfort.core.errors import AuthError

logger = logging.getLogger("authfort.validation")

# HIBP k-anonymity API. 5-char SHA-1 prefix in path; response is newline-separated
# "<35-char-suffix>:<count>" lines. Add-Padding header pads response to a uniform
# size so observers can't infer prefix popularity.
_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# Process-global state for HIBP. Initialized lazily on first call.
_hibp_semaphore: asyncio.Semaphore | None = None
_hibp_semaphore_limit: int | None = None
# Cache: prefix -> (set of suffixes, expires_at_monotonic).
_hibp_cache: dict[str, tuple[frozenset[str], float]] = {}
_HIBP_CACHE_MAX = 512


def _get_hibp_semaphore(limit: int) -> asyncio.Semaphore:
    """Lazily create a process-global semaphore for outbound HIBP concurrency.

    The first call wins — subsequent limit changes are ignored. In practice
    AuthFort is instantiated once per process, so this is fine.
    """
    global _hibp_semaphore, _hibp_semaphore_limit
    if _hibp_semaphore is None:
        _hibp_semaphore = asyncio.Semaphore(max(1, limit))
        _hibp_semaphore_limit = limit
    return _hibp_semaphore


def _cache_get(prefix: str) -> frozenset[str] | None:
    entry = _hibp_cache.get(prefix)
    if entry is None:
        return None
    suffixes, expires_at = entry
    if time.monotonic() >= expires_at:
        _hibp_cache.pop(prefix, None)
        return None
    return suffixes


def _cache_put(prefix: str, suffixes: frozenset[str], ttl: float) -> None:
    if ttl <= 0:
        return
    # Simple bound: if we hit the cap, drop the oldest-expiring entry.
    if len(_hibp_cache) >= _HIBP_CACHE_MAX:
        oldest_key = min(_hibp_cache, key=lambda k: _hibp_cache[k][1])
        _hibp_cache.pop(oldest_key, None)
    _hibp_cache[prefix] = (suffixes, time.monotonic() + ttl)

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
    except Exception:
        # Defensive: any other exception (UnicodeError, idna failures, etc.)
        # must surface as a clean 400, never a 500 from the request path.
        raise AuthError("Invalid email address", code="invalid_email", status_code=400)


async def validate_user_email_with_deliverability(
    email: str,
    *,
    check_deliverability: bool,
    fail_open: bool,
) -> str:
    """Validate email, optionally checking MX deliverability.

    When check_deliverability is False this is equivalent to validate_user_email.
    When True, the MX lookup (blocking DNS inside email-validator) runs in a
    thread. On DNS/timeout failure, fail_open=True falls back to syntax-only.
    """
    # Syntax + length guards first (cheap, sync).
    normalized = validate_user_email(email)

    if not check_deliverability:
        return normalized

    def _check() -> None:
        # Re-validate with deliverability. Discard result — normalization
        # already happened above.
        validate_email(normalized, check_deliverability=True)

    try:
        await asyncio.to_thread(_check)
        return normalized
    except EmailNotValidError:
        # Deliverability-specific failure (e.g., no MX record).
        raise AuthError("Invalid email address", code="invalid_email", status_code=400)
    except Exception:
        # DNS timeout / resolver error / anything else.
        if fail_open:
            return normalized
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


async def check_pwned_password(
    password: str,
    *,
    timeout: float = 2.0,
    fail_open: bool = True,
    max_concurrency: int = 30,
    cache_ttl: float = 300.0,
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """Check if password appears in the HIBP breach corpus via k-anonymity.

    Returns True if the password appears in at least one known breach
    (caller should reject). Returns False if not seen or — with fail_open=True —
    the HIBP service is unreachable.

    The full password never leaves the process; only the first 5 chars of its
    SHA-1 hash travel to HIBP. SHA-1 is the HIBP protocol, not a hash-strength
    choice.
    """
    # SHA-1 is required by the HIBP protocol. Not a security hash choice.
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix, suffix = sha1[:5], sha1[5:]

    # Cache hit?
    cached = _cache_get(prefix)
    if cached is not None:
        return suffix in cached

    semaphore = _get_hibp_semaphore(max_concurrency)

    owns_client = http_client is None

    async def _fetch(client: httpx.AsyncClient) -> frozenset[str] | None:
        try:
            resp = await client.get(
                _HIBP_URL.format(prefix=prefix),
                headers={"Add-Padding": "true"},
                timeout=timeout,
            )
        except Exception as e:
            logger.warning("hibp_unreachable", extra={"error": str(e)})
            return None
        if resp.status_code != 200:
            logger.warning(
                "hibp_unexpected_status", extra={"status": resp.status_code},
            )
            return None
        suffixes = set()
        for line in resp.text.splitlines():
            parts = line.split(":", 1)
            if parts:
                suffixes.add(parts[0].strip().upper())
        return frozenset(suffixes)

    async with semaphore:
        if http_client is not None:
            suffixes = await _fetch(http_client)
        else:
            async with httpx.AsyncClient() as client:
                suffixes = await _fetch(client)

    if suffixes is None:
        # HIBP unreachable / unexpected status.
        # fail_open=True → allow (return False). fail_open=False → reject.
        return not fail_open

    _cache_put(prefix, suffixes, cache_ttl)
    return suffix in suffixes
