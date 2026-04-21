"""Tests for input validation and sanitization — covers VAPT findings.

Tests XSS in names, SQL injection in emails, email header injection,
XXE payloads, invalid URLs, password length, and phone sanitization.
"""

import uuid

import pytest
import pytest_asyncio

from authfort.core.errors import AuthError
from authfort.core.validation import (
    sanitize_name,
    sanitize_phone,
    validate_avatar_url,
    validate_password,
    validate_user_email,
    validate_user_email_with_deliverability,
)
from conftest import unique_email

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

class TestEmailValidation:
    """Tests for validate_user_email."""

    def test_valid_email(self):
        assert validate_user_email("user@example.com") == "user@example.com"

    def test_email_normalized_lowercase(self):
        assert validate_user_email("User@Example.COM") == "user@example.com"

    def test_email_stripped(self):
        assert validate_user_email("  user@example.com  ") == "user@example.com"

    def test_empty_email(self):
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("")

    def test_no_at_sign(self):
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("userexample.com")

    def test_sql_injection_in_email(self):
        """VAPT: SQL injection payload in email field."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email(
                "fahad@macksofy.com;declare @q varchar(99);set @q='\\ddumgjlhsyco6eipem9On6bznqtohpcd35rxen2c.oasti+fy.com|egf'; exec master.dbo.xp_dirtree @q;--"
            )

    def test_xxe_injection_in_email(self):
        """VAPT: XXE payload in email field."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email(
                "fahad@macksofy.com||(select extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"utf-8\"?><!doctype root'), '/l') from dual)||"
            )

    def test_xss_script_in_email(self):
        """VAPT: XSS script tag in email field."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("fahad@macksofy.com,<script>alert(1)</script>")

    def test_xss_img_in_email(self):
        """VAPT: XSS img tag in email field."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("fahad@macksofy.com,<img>alert(1)>")

    def test_email_header_injection(self):
        """VAPT: Email header injection payload."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("fahad@macksofy.com subject: hacked injectedbody")

    def test_multiple_emails_comma(self):
        """VAPT: Multiple emails separated by comma."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("victim@example.com, attacker@example.com")

    def test_multiple_emails_url_encoded(self):
        """VAPT: URL-encoded comma to inject second email."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("victim@example.com%2cattacker@example.com")

    def test_email_with_url(self):
        """VAPT: Email followed by URL."""
        with pytest.raises(AuthError, match="Invalid email"):
            validate_user_email("victim@example.com, https://lmbnj43lqp7l7svy23mdinbxcoif66uv.oastify.com")

    def test_email_too_long(self):
        with pytest.raises(AuthError, match="too long"):
            validate_user_email("a" * 250 + "@example.com")

    # VAPT: inputs that previously bubbled as 500 must surface as 400 invalid_email.

    def test_malformed_localhost(self):
        with pytest.raises(AuthError) as exc_info:
            validate_user_email("test@localhost")
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400

    def test_malformed_single_char_domain(self):
        with pytest.raises(AuthError) as exc_info:
            validate_user_email("a@b")
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400

    def test_malformed_just_text(self):
        with pytest.raises(AuthError) as exc_info:
            validate_user_email("just-text")
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400

    def test_non_string_input_raises_400(self):
        with pytest.raises(AuthError) as exc_info:
            validate_user_email(12345)  # type: ignore[arg-type]
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400

    def test_none_input_raises_400(self):
        with pytest.raises(AuthError) as exc_info:
            validate_user_email(None)  # type: ignore[arg-type]
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400

    def test_unexpected_exception_becomes_400(self, monkeypatch):
        """If email-validator raises something other than EmailNotValidError, still 400."""
        from authfort.core import validation as validation_mod

        def raise_weird(*args, **kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(validation_mod, "validate_email", raise_weird)
        with pytest.raises(AuthError) as exc_info:
            validate_user_email("user@example.com")
        assert exc_info.value.code == "invalid_email"
        assert exc_info.value.status_code == 400


class TestDeliverabilityCheck:
    """Tests for validate_user_email_with_deliverability."""

    async def test_disabled_flag_skips_dns(self, monkeypatch):
        from authfort.core import validation as validation_mod

        def fail_if_called(*args, **kwargs):
            # Syntax validation uses check_deliverability=False. Fail only
            # on deliverability checks.
            if kwargs.get("check_deliverability"):
                raise AssertionError("DNS should not be consulted when flag is off")
            # Fall through to the real validator for syntax validation.
            from email_validator import validate_email as real
            return real(*args, **kwargs)

        monkeypatch.setattr(validation_mod, "validate_email", fail_if_called)

        result = await validate_user_email_with_deliverability(
            "user@example.com", check_deliverability=False, fail_open=True,
        )
        assert result == "user@example.com"

    async def test_mx_failure_fail_open_allows(self, monkeypatch):
        from authfort.core import validation as validation_mod
        from email_validator import EmailNotValidError, validate_email as real_validate

        def fake_validate(*args, **kwargs):
            if kwargs.get("check_deliverability"):
                # Simulate DNS timeout / resolver error.
                raise RuntimeError("dns timeout")
            return real_validate(*args, **kwargs)

        monkeypatch.setattr(validation_mod, "validate_email", fake_validate)

        result = await validate_user_email_with_deliverability(
            "user@example.com", check_deliverability=True, fail_open=True,
        )
        assert result == "user@example.com"

    async def test_mx_failure_fail_closed_rejects(self, monkeypatch):
        from authfort.core import validation as validation_mod
        from email_validator import validate_email as real_validate

        def fake_validate(*args, **kwargs):
            if kwargs.get("check_deliverability"):
                raise RuntimeError("dns timeout")
            return real_validate(*args, **kwargs)

        monkeypatch.setattr(validation_mod, "validate_email", fake_validate)

        with pytest.raises(AuthError) as exc_info:
            await validate_user_email_with_deliverability(
                "user@example.com", check_deliverability=True, fail_open=False,
            )
        assert exc_info.value.code == "invalid_email"

    async def test_no_mx_rejected(self, monkeypatch):
        from authfort.core import validation as validation_mod
        from email_validator import EmailNotValidError, validate_email as real_validate

        def fake_validate(*args, **kwargs):
            if kwargs.get("check_deliverability"):
                raise EmailNotValidError("The domain name k does not exist.")
            return real_validate(*args, **kwargs)

        monkeypatch.setattr(validation_mod, "validate_email", fake_validate)

        with pytest.raises(AuthError) as exc_info:
            await validate_user_email_with_deliverability(
                "k@k.k", check_deliverability=True, fail_open=True,
            )
        assert exc_info.value.code == "invalid_email"


# ---------------------------------------------------------------------------
# Name sanitization
# ---------------------------------------------------------------------------

class TestNameSanitization:
    """Tests for sanitize_name."""

    def test_normal_name(self):
        assert sanitize_name("John Doe") == "John Doe"

    def test_none_returns_none(self):
        assert sanitize_name(None) is None

    def test_empty_returns_none(self):
        assert sanitize_name("") is None

    def test_whitespace_returns_none(self):
        assert sanitize_name("   ") is None

    def test_xss_svg_onload(self):
        """VAPT: XSS via SVG onload."""
        result = sanitize_name("<svg onload=alert(1)>")
        # nh3 strips all tags, leaving empty string → None
        assert result is None

    def test_xss_script_tag(self):
        """VAPT: XSS via script tag."""
        result = sanitize_name("<script>alert(1)</script>")
        assert result is None

    def test_xss_img_tag(self):
        """VAPT: XSS via img tag."""
        result = sanitize_name("<img src=x onerror=alert(1)>")
        assert result is None

    def test_mixed_text_and_html(self):
        """Name with some HTML mixed in."""
        result = sanitize_name("John <b>Doe</b>")
        assert result == "John Doe"

    def test_html_entities_preserved(self):
        """Legitimate names with special characters."""
        result = sanitize_name("O'Brien")
        assert result == "O'Brien"

    def test_name_with_accents(self):
        result = sanitize_name("José García")
        assert result == "José García"

    def test_name_too_long(self):
        with pytest.raises(AuthError, match="characters or fewer"):
            sanitize_name("A" * 256)

    def test_control_characters_stripped(self):
        result = sanitize_name("John\x00\x01Doe")
        assert result == "JohnDoe"

    def test_whitespace_normalized(self):
        result = sanitize_name("  John    Doe  ")
        assert result == "John Doe"

    def test_sql_injection_in_name(self):
        """SQL injection payload in name — stored as literal text, tags stripped."""
        result = sanitize_name("'; DROP TABLE users; --")
        assert result == "'; DROP TABLE users; --"


# ---------------------------------------------------------------------------
# Phone sanitization
# ---------------------------------------------------------------------------

class TestPhoneSanitization:
    """Tests for sanitize_phone."""

    def test_valid_phone(self):
        assert sanitize_phone("+1 (555) 123-4567") == "+1 (555) 123-4567"

    def test_none_returns_none(self):
        assert sanitize_phone(None) is None

    def test_empty_returns_none(self):
        assert sanitize_phone("") is None

    def test_international_phone(self):
        assert sanitize_phone("+91 98765 43210") == "+91 98765 43210"

    def test_xss_in_phone(self):
        # nh3 strips script tags and content, leaving empty → None
        assert sanitize_phone("<script>alert(1)</script>") is None

    def test_letters_in_phone(self):
        with pytest.raises(AuthError, match="invalid characters"):
            sanitize_phone("555-HACK")

    def test_phone_too_long(self):
        with pytest.raises(AuthError, match="characters or fewer"):
            sanitize_phone("+" + "1" * 50)


# ---------------------------------------------------------------------------
# Avatar URL validation
# ---------------------------------------------------------------------------

class TestAvatarUrlValidation:
    """Tests for validate_avatar_url."""

    def test_valid_https_url(self):
        assert validate_avatar_url("https://example.com/avatar.png") == "https://example.com/avatar.png"

    def test_valid_http_url(self):
        assert validate_avatar_url("http://example.com/avatar.png") == "http://example.com/avatar.png"

    def test_none_returns_none(self):
        assert validate_avatar_url(None) is None

    def test_empty_returns_none(self):
        assert validate_avatar_url("") is None

    def test_javascript_url(self):
        with pytest.raises(AuthError, match="valid http or https"):
            validate_avatar_url("javascript:alert(1)")

    def test_data_url(self):
        with pytest.raises(AuthError, match="valid http or https"):
            validate_avatar_url("data:image/png;base64,AAAA")

    def test_ftp_url(self):
        with pytest.raises(AuthError, match="valid http or https"):
            validate_avatar_url("ftp://evil.com/file")

    def test_no_scheme(self):
        with pytest.raises(AuthError, match="valid http or https"):
            validate_avatar_url("example.com/avatar.png")

    def test_url_too_long(self):
        with pytest.raises(AuthError, match="too long"):
            validate_avatar_url("https://example.com/" + "a" * 2050)


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

class TestPasswordValidation:
    """Tests for validate_password."""

    def test_valid_password(self):
        assert validate_password("MyStr0ngP@ss") == "MyStr0ngP@ss"

    def test_min_length_default(self):
        with pytest.raises(AuthError, match="at least 8"):
            validate_password("short")

    def test_exactly_min_length(self):
        assert validate_password("12345678") == "12345678"

    def test_custom_min_length(self):
        with pytest.raises(AuthError, match="at least 12"):
            validate_password("short1234", min_length=12)

    def test_empty_password(self):
        with pytest.raises(AuthError, match="at least 8"):
            validate_password("")


# ---------------------------------------------------------------------------
# Integration tests — validation through HTTP endpoints
# ---------------------------------------------------------------------------

class TestSignupValidation:
    """Test that validation is enforced through the signup endpoint."""

    async def test_signup_rejects_xss_in_name(self, client):
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "StrongPassword1!",
            "name": "<svg onload=alert(1)>",
        })
        # Should succeed but with sanitized (empty → null) name
        assert r.status_code == 201
        assert r.json()["user"]["name"] is None

    async def test_signup_rejects_script_in_name(self, client):
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "StrongPassword1!",
            "name": "<script>alert(1)</script>",
        })
        assert r.status_code == 201
        assert r.json()["user"]["name"] is None

    async def test_signup_sanitizes_html_in_name(self, client):
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "StrongPassword1!",
            "name": "John <b>Doe</b>",
        })
        assert r.status_code == 201
        assert r.json()["user"]["name"] == "John Doe"

    async def test_signup_rejects_sql_injection_email(self, client):
        r = await client.post("/auth/signup", json={
            "email": "fahad@macksofy.com;declare @q varchar(99);exec master.dbo.xp_dirtree @q;--",
            "password": "StrongPassword1!",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_email"

    async def test_signup_rejects_xss_in_email(self, client):
        r = await client.post("/auth/signup", json={
            "email": "fahad@macksofy.com,<script>alert(1)</script>",
            "password": "StrongPassword1!",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_email"

    async def test_signup_rejects_header_injection_email(self, client):
        r = await client.post("/auth/signup", json={
            "email": "fahad@macksofy.com subject: hacked injectedbody",
            "password": "StrongPassword1!",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_email"

    async def test_signup_rejects_short_password(self, client):
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "short",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "password_too_short"

    async def test_signup_rejects_invalid_avatar_url(self, client):
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "StrongPassword1!",
            "avatar_url": "javascript:alert(1)",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_avatar_url"

    async def test_signup_sanitizes_xss_in_phone(self, client):
        """XSS in phone gets stripped to empty → stored as null."""
        r = await client.post("/auth/signup", json={
            "email": unique_email(),
            "password": "StrongPassword1!",
            "phone": "<script>alert(1)</script>",
        })
        assert r.status_code == 201
        assert r.json()["user"]["phone"] is None

    async def test_signup_valid_input(self, client):
        """Normal signup still works correctly."""
        email = unique_email()
        r = await client.post("/auth/signup", json={
            "email": email,
            "password": "StrongPassword1!",
            "name": "Test User",
            "phone": "+1 555-0123",
            "avatar_url": "https://example.com/avatar.png",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["user"]["email"] == email
        assert data["user"]["name"] == "Test User"
        assert data["user"]["phone"] == "+1 555-0123"
        assert data["user"]["avatar_url"] == "https://example.com/avatar.png"


class TestLoginValidation:
    """Test that email validation is enforced on login."""

    async def test_login_rejects_sql_injection_email(self, client):
        r = await client.post("/auth/login", json={
            "email": "'; DROP TABLE users; --",
            "password": "whatever123",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_email"
