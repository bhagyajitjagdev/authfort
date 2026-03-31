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
