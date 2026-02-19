"""Tests for CookieConfig domain field."""

import os
import tempfile
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthFort, CookieConfig

pytestmark = pytest.mark.asyncio


_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
_TEST_URL = f"sqlite+aiosqlite:///{_tmp.name}"


@pytest.fixture(scope="session", autouse=True)
def _cleanup():
    yield
    if os.path.exists(_tmp.name):
        os.remove(_tmp.name)


@pytest_asyncio.fixture
async def auth_with_domain():
    """AuthFort with cookie domain set."""
    instance = AuthFort(
        database_url=_TEST_URL,
        cookie=CookieConfig(secure=False, domain=".example.com"),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def domain_client(auth_with_domain: AuthFort):
    app = FastAPI()
    app.include_router(auth_with_domain.fastapi_router(), prefix="/auth")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        yield client


class TestCookieDomain:
    async def test_cookie_domain_set(self, domain_client: AsyncClient):
        """When domain is configured, Set-Cookie includes the domain."""
        email = f"test-{uuid.uuid4().hex[:8]}@example.com"
        resp = await domain_client.post("/auth/signup", json={
            "email": email, "password": "password123",
        })
        assert resp.status_code == 201

        set_cookies = resp.headers.get_list("set-cookie")
        assert len(set_cookies) >= 2
        for cookie_header in set_cookies:
            assert ".example.com" in cookie_header.lower()

    async def test_cookie_domain_none_default(self, client: AsyncClient):
        """Default CookieConfig (no domain) does not include domain in cookies."""
        email = f"test-{uuid.uuid4().hex[:8]}@example.com"
        resp = await client.post("/auth/signup", json={
            "email": email, "password": "password123",
        })
        assert resp.status_code == 201

        set_cookies = resp.headers.get_list("set-cookie")
        assert len(set_cookies) >= 2
        for cookie_header in set_cookies:
            assert "domain=" not in cookie_header.lower()
