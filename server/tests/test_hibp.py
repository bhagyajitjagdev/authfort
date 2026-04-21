"""Tests for HIBP password breach check (Phase 14 item 2)."""

import hashlib

import httpx
import pytest
import pytest_asyncio

from authfort import AuthError, AuthFort, CookieConfig
from authfort.core.validation import check_pwned_password

from conftest import TEST_DATABASE_URL, unique_email

pytestmark = pytest.mark.asyncio


def _sha1_suffix(password: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def _mock_hibp(prefix_to_body: dict[str, str], *, status: int = 200):
    """Return an httpx MockTransport that serves prefix -> body."""

    def handler(request: httpx.Request) -> httpx.Response:
        # URL is like https://api.pwnedpasswords.com/range/ABCDE
        prefix = request.url.path.rsplit("/", 1)[-1]
        body = prefix_to_body.get(prefix, "")
        return httpx.Response(status_code=status, text=body)

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _reset_hibp_cache():
    """Ensure cache and semaphore state don't leak between tests."""
    from authfort.core import validation

    validation._hibp_cache.clear()
    validation._hibp_semaphore = None
    validation._hibp_semaphore_limit = None
    yield
    validation._hibp_cache.clear()
    validation._hibp_semaphore = None
    validation._hibp_semaphore_limit = None


@pytest.fixture(autouse=True)
def _restore_real_hibp(monkeypatch):
    """Undo the conftest-level HIBP stub so these tests exercise the real helper.

    The conftest autouse stub wins by default; we restore the real function here.
    """
    from authfort.core import validation
    import importlib

    # Reload to get the original check_pwned_password reference.
    importlib.reload(validation)


class TestCheckPwnedPassword:
    async def test_pwned_returns_true(self):
        prefix, suffix = _sha1_suffix("123456789")
        body = f"{suffix}:4876\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"
        transport = _mock_hibp({prefix: body})

        async with httpx.AsyncClient(transport=transport) as client:
            result = await check_pwned_password(
                "123456789", http_client=client, fail_open=True, cache_ttl=0,
            )
        assert result is True

    async def test_not_pwned_returns_false(self):
        prefix, _ = _sha1_suffix("a-very-unique-20char-xp-9283")
        body = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA:7"
        transport = _mock_hibp({prefix: body})

        async with httpx.AsyncClient(transport=transport) as client:
            result = await check_pwned_password(
                "a-very-unique-20char-xp-9283",
                http_client=client, fail_open=True, cache_ttl=0,
            )
        assert result is False

    async def test_network_error_fail_open_allows(self, monkeypatch):
        # Simulate transport error.
        def raise_error(request):
            raise httpx.ConnectError("network down")

        transport = httpx.MockTransport(raise_error)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await check_pwned_password(
                "anypw", http_client=client, fail_open=True, cache_ttl=0,
            )
        assert result is False  # fail_open → allow

    async def test_network_error_fail_closed_rejects(self):
        def raise_error(request):
            raise httpx.ConnectError("network down")

        transport = httpx.MockTransport(raise_error)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await check_pwned_password(
                "anypw", http_client=client, fail_open=False, cache_ttl=0,
            )
        assert result is True  # fail_closed → reject

    async def test_non_200_fail_open_allows(self):
        transport = _mock_hibp({}, status=503)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await check_pwned_password(
                "anypw", http_client=client, fail_open=True, cache_ttl=0,
            )
        assert result is False

    async def test_cache_prevents_second_call(self):
        call_count = 0
        prefix, suffix = _sha1_suffix("cachedtest1234567")
        body = f"{suffix}:10"

        def handler(request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, text=body)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            r1 = await check_pwned_password(
                "cachedtest1234567", http_client=client,
                fail_open=True, cache_ttl=300,
            )
            r2 = await check_pwned_password(
                "cachedtest1234567", http_client=client,
                fail_open=True, cache_ttl=300,
            )
        assert r1 is True
        assert r2 is True
        assert call_count == 1  # second call served from cache

    async def test_add_padding_header_sent(self):
        captured = {}

        def handler(request):
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, text="")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await check_pwned_password(
                "anypw", http_client=client, fail_open=True, cache_ttl=0,
            )
        assert captured["headers"].get("add-padding") == "true"


@pytest_asyncio.fixture
async def auth_hibp_strict(monkeypatch):
    """AuthFort with HIBP enabled (fail-closed) and a pwned-list stub."""
    # Stub the helper at the auth module import location.
    async def stub_check(password, **kwargs):
        return password in {"123456", "password", "pwnedpw1"}

    monkeypatch.setattr("authfort.core.auth.check_pwned_password", stub_check)

    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        check_pwned_passwords=True,
        pwned_check_fail_open=False,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


class TestHIBPWiring:
    async def test_signup_rejects_pwned(self, auth_hibp_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_hibp_strict.create_user(unique_email(), "pwnedpw1")
        assert exc_info.value.code == "password_pwned"
        assert exc_info.value.status_code == 400

    async def test_signup_accepts_clean_password(self, auth_hibp_strict: AuthFort):
        result = await auth_hibp_strict.create_user(unique_email(), "cleanpw1234567")
        assert result.user is not None

    async def test_admin_create_user_skips_hibp(self, auth_hibp_strict: AuthFort):
        # email_verified=True signals admin-provisioned → skip HIBP.
        result = await auth_hibp_strict.create_user(
            unique_email(), "pwnedpw1", email_verified=True,
        )
        assert result.user is not None

    async def test_change_password_rejects_pwned(self, auth_hibp_strict: AuthFort):
        email = unique_email()
        result = await auth_hibp_strict.create_user(email, "cleanpw1234567")

        with pytest.raises(AuthError) as exc_info:
            await auth_hibp_strict.change_password(
                result.user.id, "cleanpw1234567", "pwnedpw1",
            )
        assert exc_info.value.code == "password_pwned"

    async def test_reset_password_rejects_pwned(self, auth_hibp_strict: AuthFort):
        email = unique_email()
        await auth_hibp_strict.create_user(email, "cleanpw1234567")
        token = await auth_hibp_strict.create_password_reset_token(email)

        with pytest.raises(AuthError) as exc_info:
            await auth_hibp_strict.reset_password(token, "pwnedpw1")
        assert exc_info.value.code == "password_pwned"

    async def test_event_emitted_on_pwned_signup(self, auth_hibp_strict: AuthFort):
        events = []
        auth_hibp_strict.add_hook(
            "password_pwned_rejected", lambda e: events.append(e),
        )

        with pytest.raises(AuthError):
            await auth_hibp_strict.create_user(unique_email(), "pwnedpw1")

        assert len(events) == 1
        # Should be a SHA-256 hex.
        assert len(events[0].email_hash) == 64
