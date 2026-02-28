"""Tests for reverse proxy IP extraction and trusted proxy support."""

import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthFort, CookieConfig, RateLimitConfig
from authfort.config import AuthFortConfig
from authfort.integrations.fastapi.proxy import get_client_ip

pytestmark = pytest.mark.asyncio

from conftest import TEST_DATABASE_URL


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(host: str | None, headers: dict | None = None) -> MagicMock:
    """Create a mock Request with the given client host and headers."""
    request = MagicMock()
    if host is None:
        request.client = None
    else:
        request.client.host = host
    request.headers = headers or {}
    return request


def _make_config(**overrides) -> AuthFortConfig:
    return AuthFortConfig(database_url="sqlite+aiosqlite:///test.db", **overrides)


# ---------------------------------------------------------------------------
# Unit tests: get_client_ip — no proxy config
# ---------------------------------------------------------------------------

class TestNoProxyConfig:
    def test_returns_direct_ip(self):
        request = _make_request("1.2.3.4")
        config = _make_config()
        assert get_client_ip(request, config) == "1.2.3.4"

    def test_ignores_forwarded_for_header(self):
        request = _make_request("1.2.3.4", {"x-forwarded-for": "9.9.9.9"})
        config = _make_config()
        assert get_client_ip(request, config) == "1.2.3.4"

    def test_ignores_real_ip_header(self):
        request = _make_request("1.2.3.4", {"x-real-ip": "9.9.9.9"})
        config = _make_config()
        assert get_client_ip(request, config) == "1.2.3.4"

    def test_none_when_no_client(self):
        request = _make_request(None)
        config = _make_config()
        assert get_client_ip(request, config) is None


# ---------------------------------------------------------------------------
# Unit tests: get_client_ip — trust_proxy=True
# ---------------------------------------------------------------------------

class TestTrustProxy:
    def test_reads_x_forwarded_for(self):
        request = _make_request("10.0.0.1", {"x-forwarded-for": "203.0.113.1"})
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_reads_first_from_chain(self):
        request = _make_request("10.0.0.1", {"x-forwarded-for": "203.0.113.1, 10.0.0.2, 10.0.0.1"})
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_reads_x_real_ip(self):
        request = _make_request("10.0.0.1", {"x-real-ip": "203.0.113.50"})
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "203.0.113.50"

    def test_forwarded_for_takes_precedence(self):
        request = _make_request("10.0.0.1", {
            "x-forwarded-for": "203.0.113.1",
            "x-real-ip": "203.0.113.50",
        })
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_strips_whitespace(self):
        request = _make_request("10.0.0.1", {"x-forwarded-for": "  203.0.113.1 , 10.0.0.2 "})
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_falls_back_to_direct_ip(self):
        request = _make_request("10.0.0.1")
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) == "10.0.0.1"

    def test_none_when_no_client(self):
        request = _make_request(None)
        config = _make_config(trust_proxy=True)
        assert get_client_ip(request, config) is None


# ---------------------------------------------------------------------------
# Unit tests: get_client_ip — trusted_proxies (strict mode)
# ---------------------------------------------------------------------------

class TestTrustedProxies:
    def test_exact_ip_trusted(self):
        import ipaddress
        networks = (ipaddress.ip_network("172.18.0.1"),)
        request = _make_request("172.18.0.1", {"x-forwarded-for": "203.0.113.1"})
        config = _make_config(trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_cidr_trusted(self):
        import ipaddress
        networks = (ipaddress.ip_network("172.18.0.0/16"),)
        request = _make_request("172.18.5.10", {"x-forwarded-for": "203.0.113.1"})
        config = _make_config(trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_untrusted_ip_ignores_headers(self):
        """Spoofing prevention: untrusted source IP → ignore proxy headers."""
        import ipaddress
        networks = (ipaddress.ip_network("10.0.0.0/8"),)
        request = _make_request("8.8.8.8", {"x-forwarded-for": "9.9.9.9"})
        config = _make_config(trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "8.8.8.8"

    def test_multiple_networks(self):
        import ipaddress
        networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
        )
        request = _make_request("172.18.0.1", {"x-forwarded-for": "203.0.113.1"})
        config = _make_config(trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_trusted_proxies_overrides_trust_proxy_false(self):
        """trusted_proxy_networks takes effect even when trust_proxy is False."""
        import ipaddress
        networks = (ipaddress.ip_network("10.0.0.0/8"),)
        request = _make_request("10.0.0.1", {"x-forwarded-for": "203.0.113.1"})
        config = _make_config(trust_proxy=False, trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_falls_back_when_no_headers(self):
        import ipaddress
        networks = (ipaddress.ip_network("10.0.0.0/8"),)
        request = _make_request("10.0.0.1")
        config = _make_config(trusted_proxy_networks=networks)
        assert get_client_ip(request, config) == "10.0.0.1"


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestConfigValidation:
    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError, match="Invalid IP/CIDR"):
            AuthFort(
                database_url=TEST_DATABASE_URL,
                trusted_proxies=["not-an-ip"],
            )

    def test_valid_single_ip_parsed(self):
        """A single IP like '10.0.0.1' is parsed as /32."""
        instance = AuthFort(
            database_url=TEST_DATABASE_URL,
            trusted_proxies=["10.0.0.1"],
        )
        assert len(instance.config.trusted_proxy_networks) == 1

    def test_valid_cidr_parsed(self):
        instance = AuthFort(
            database_url=TEST_DATABASE_URL,
            trusted_proxies=["172.18.0.0/16", "10.0.0.0/8"],
        )
        assert len(instance.config.trusted_proxy_networks) == 2


# ---------------------------------------------------------------------------
# Integration tests: proxy headers with rate limiting
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def auth_trust_proxy():
    """AuthFort with trust_proxy and tight rate limits."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        trust_proxy=True,
        rate_limit=RateLimitConfig(login="2/min"),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def trust_proxy_client(auth_trust_proxy: AuthFort):
    app = FastAPI()
    app.include_router(auth_trust_proxy.fastapi_router(), prefix="/auth")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


class TestProxyIntegration:
    async def test_rate_limit_uses_forwarded_ip(
        self, auth_trust_proxy: AuthFort, trust_proxy_client: AsyncClient,
    ):
        """Different X-Forwarded-For IPs get separate rate limit buckets."""
        # Use different emails per IP to avoid hitting the email-based rate limit
        email_a = unique_email()
        email_b = unique_email()
        await auth_trust_proxy.create_user(email_a, "password123")
        await auth_trust_proxy.create_user(email_b, "password123")

        # 2 requests from IP-A (limit is 2/min)
        for _ in range(2):
            resp = await trust_proxy_client.post(
                "/auth/login",
                json={"email": email_a, "password": "wrong"},
                headers={"X-Forwarded-For": "203.0.113.1"},
            )
            assert resp.status_code != 429

        # 3rd request from IP-A → rate limited
        resp = await trust_proxy_client.post(
            "/auth/login",
            json={"email": email_a, "password": "wrong"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        )
        assert resp.status_code == 429

        # Request from IP-B with different email → separate bucket, not rate limited
        resp = await trust_proxy_client.post(
            "/auth/login",
            json={"email": email_b, "password": "wrong"},
            headers={"X-Forwarded-For": "203.0.113.2"},
        )
        assert resp.status_code != 429

    async def test_event_has_forwarded_ip(
        self, auth_trust_proxy: AuthFort, trust_proxy_client: AsyncClient,
    ):
        """login_failed event should contain the forwarded IP, not 127.0.0.1."""
        events = []
        auth_trust_proxy.add_hook("login_failed", lambda e: events.append(e))

        email = unique_email()
        await auth_trust_proxy.create_user(email, "password123")

        await trust_proxy_client.post(
            "/auth/login",
            json={"email": email, "password": "wrong"},
            headers={"X-Forwarded-For": "198.51.100.42"},
        )

        assert len(events) == 1
        assert events[0].ip_address == "198.51.100.42"


@pytest_asyncio.fixture
async def auth_trusted_proxies():
    """AuthFort with trusted_proxies (strict mode) and tight rate limits."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        # Test client connects as 127.0.0.1, which is in 127.0.0.0/8
        trusted_proxies=["127.0.0.0/8"],
        rate_limit=RateLimitConfig(login="2/min"),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def trusted_proxies_client(auth_trusted_proxies: AuthFort):
    app = FastAPI()
    app.include_router(auth_trusted_proxies.fastapi_router(), prefix="/auth")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


class TestTrustedProxiesIntegration:
    async def test_reads_header_from_trusted_proxy(
        self, auth_trusted_proxies: AuthFort, trusted_proxies_client: AsyncClient,
    ):
        """Test client is 127.0.0.1 (trusted), so headers should be read."""
        events = []
        auth_trusted_proxies.add_hook("login_failed", lambda e: events.append(e))

        email = unique_email()
        await auth_trusted_proxies.create_user(email, "password123")

        await trusted_proxies_client.post(
            "/auth/login",
            json={"email": email, "password": "wrong"},
            headers={"X-Forwarded-For": "198.51.100.99"},
        )

        assert len(events) == 1
        assert events[0].ip_address == "198.51.100.99"
