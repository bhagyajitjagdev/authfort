"""Test fixtures for AuthFort server integration tests."""

import os
import tempfile
import uuid

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthFort, CookieConfig
from authfort.core.schemas import UserResponse

pytestmark = pytest.mark.asyncio

# If DATABASE_URL=sqlite, auto-create a temp file for the test session.
# For PostgreSQL, use the URL as-is.
_raw_url = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/authfort",
)

_sqlite_tmp = None
if _raw_url.startswith("sqlite"):
    _sqlite_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    _sqlite_tmp.close()
    TEST_DATABASE_URL = f"sqlite+aiosqlite:///{_sqlite_tmp.name}"
else:
    TEST_DATABASE_URL = _raw_url


@pytest.fixture(scope="session", autouse=True)
def _cleanup_sqlite():
    """Delete the temp SQLite file after all tests finish."""
    yield
    if _sqlite_tmp is not None and os.path.exists(_sqlite_tmp.name):
        os.remove(_sqlite_tmp.name)


@pytest_asyncio.fixture
async def auth():
    """Create an AuthFort instance for testing."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def client(auth: AuthFort):
    """Async HTTP client for testing against the FastAPI app."""
    app = FastAPI()
    app.include_router(auth.fastapi_router(), prefix="/auth")
    app.include_router(auth.jwks_router())

    # Role-protected test endpoint
    @app.get("/test-admin")
    async def test_admin(user: UserResponse = Depends(auth.require_role("admin"))):
        return {"message": "admin access", "roles": user.roles}

    # Multi-role test endpoint (admin OR editor)
    @app.get("/test-content")
    async def test_content(user: UserResponse = Depends(auth.require_role(["admin", "editor"]))):
        return {"message": "content access", "roles": user.roles}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def auth_with_secret():
    """AuthFort instance with introspection secret for testing."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        introspect_secret="test-secret-123",
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def secret_client(auth_with_secret: AuthFort):
    """HTTP client for testing with introspection secret."""
    app = FastAPI()
    app.include_router(auth_with_secret.fastapi_router(), prefix="/auth")
    app.include_router(auth_with_secret.jwks_router())

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def auth_with_oauth():
    """AuthFort instance with mock OAuth providers for testing."""
    from authfort import GitHubProvider, GoogleProvider

    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        providers=[
            GoogleProvider(client_id="test-google-id", client_secret="test-google-secret"),
            GitHubProvider(client_id="test-github-id", client_secret="test-github-secret"),
        ],
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def oauth_client(auth_with_oauth: AuthFort):
    """Async HTTP client for testing OAuth flows."""
    app = FastAPI()
    app.include_router(auth_with_oauth.fastapi_router(), prefix="/auth")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def auth_no_signup():
    """AuthFort instance with signup disabled."""
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        allow_signup=False,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def client_no_signup(auth_no_signup: AuthFort):
    """HTTP client for testing with signup disabled."""
    app = FastAPI()
    app.include_router(auth_no_signup.fastapi_router(), prefix="/auth")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


def unique_email() -> str:
    """Generate a unique email for each test to avoid conflicts."""
    return f"test-{uuid.uuid4().hex[:8]}@example.com"
