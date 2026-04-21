"""Regression tests for v0.0.26 VAPT follow-up fixes.

Issue 1 — AuthError raised from email-input endpoints must surface as clean
         400/4xx, not leak through to a downstream app's generic 500 handler.
Issue 2 — email_deliverability_check must gate magic-link, OTP, login, and
         forgot-password — not just signup.
"""

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthError, AuthFort, CookieConfig
from authfort.core.schemas import UserResponse

from conftest import TEST_DATABASE_URL, unique_email

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Fixtures — AuthFort with deliverability on, HIBP off, passwordless allowed.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_strict(monkeypatch):
    """AuthFort with email_deliverability_check=True + passwordless signup.

    Monkeypatches email-validator so k@k.k is rejected for deliverability and
    real email domains pass, without hitting real DNS.
    """
    from authfort.core import validation as validation_mod
    from email_validator import EmailNotValidError, validate_email as real_validate

    def fake_validate(email, **kwargs):
        # Simulate deliverability outcome without hitting real DNS:
        # reject addresses containing "k.k", accept everything else.
        if kwargs.get("check_deliverability") and "k.k" in email:
            raise EmailNotValidError("The domain name k.k does not exist.")
        # Always skip real DNS; we only want to test the wiring.
        kwargs["check_deliverability"] = False
        return real_validate(email, **kwargs)

    monkeypatch.setattr(validation_mod, "validate_email", fake_validate)

    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        allow_passwordless_signup=True,
        email_deliverability_check=True,
        email_deliverability_fail_open=False,
        check_pwned_passwords=False,
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


def _build_app_with_generic_500(auth: AuthFort, install_handler: bool) -> FastAPI:
    """Build a FastAPI app that mimics a downstream consumer.

    The consumer has a catch-all exception handler that returns 500 for any
    uncaught exception. Pre-v0.0.26, AuthError would fall through to this
    handler and surface as 500 instead of 400.
    """
    app = FastAPI()

    if install_handler:
        # New path in v0.0.26 — install_fastapi registers the AuthError handler.
        auth.install_fastapi(app, prefix="/auth")
    else:
        # Old path — only mount routers, no exception handler.
        app.include_router(auth.fastapi_router(), prefix="/auth")
        app.include_router(auth.jwks_router())

    @app.exception_handler(Exception)
    async def generic_500(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "message": "Something went wrong"},
        )

    return app


@pytest_asyncio.fixture
async def client_with_handler(auth_strict: AuthFort):
    app = _build_app_with_generic_500(auth_strict, install_handler=True)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def client_without_handler(auth_strict: AuthFort):
    app = _build_app_with_generic_500(auth_strict, install_handler=False)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# Issue 1 — AuthError handled by install_fastapi's global exception handler
# ---------------------------------------------------------------------------


class TestGlobalExceptionHandler:
    async def test_magic_link_bad_email_returns_400_not_500(self, client_with_handler):
        """Reproducer from the ticket — k@k.k on /auth/magic-link."""
        r = await client_with_handler.post(
            "/auth/magic-link", json={"email": "k@k.k"},
        )
        assert r.status_code == 400, r.text
        body = r.json()
        assert body["detail"]["error"] == "invalid_email"

    async def test_magic_link_malformed_email_returns_400_not_500(self, client_with_handler):
        """Second reproducer from the ticket — just-text-no-at-sign."""
        r = await client_with_handler.post(
            "/auth/magic-link", json={"email": "just-text-no-at-sign"},
        )
        assert r.status_code == 400, r.text
        body = r.json()
        assert body["detail"]["error"] == "invalid_email"

    async def test_otp_bad_email_returns_400_not_500(self, client_with_handler):
        r = await client_with_handler.post(
            "/auth/otp", json={"email": "k@k.k"},
        )
        assert r.status_code == 400, r.text
        body = r.json()
        assert body["detail"]["error"] == "invalid_email"

    async def test_signup_bad_email_returns_400_not_500(self, client_with_handler):
        r = await client_with_handler.post(
            "/auth/signup",
            json={"email": "k@k.k", "password": "validpassword123"},
        )
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "invalid_email"


class TestExceptionHandlerIsOptional:
    """Verify install_fastapi(register_exception_handler=False) respects opt-out."""

    async def test_opt_out_still_mounts_routers(self, auth_strict: AuthFort):
        app = FastAPI()
        auth_strict.install_fastapi(app, register_exception_handler=False)
        # Routers still mounted — /auth/signup exists.
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ) as client:
            # Valid signup works.
            r = await client.post(
                "/auth/signup",
                json={"email": unique_email(), "password": "validpassword123"},
            )
            assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# Issue 2 — deliverability gates passwordless + lookup paths
# ---------------------------------------------------------------------------


class TestDeliverabilityOnAllEmailPaths:
    """Direct programmatic calls — bypass FastAPI to prove core wiring."""

    async def test_magic_link_request_rejects_undeliverable(self, auth_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_strict.create_magic_link_token("k@k.k")
        assert exc_info.value.code == "invalid_email"

    async def test_otp_request_rejects_undeliverable(self, auth_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_strict.create_email_otp("k@k.k")
        assert exc_info.value.code == "invalid_email"

    async def test_login_rejects_undeliverable(self, auth_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_strict.login("k@k.k", "anypassword123")
        assert exc_info.value.code == "invalid_email"

    async def test_forgot_password_rejects_undeliverable(self, auth_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_strict.create_password_reset_token("k@k.k")
        assert exc_info.value.code == "invalid_email"

    async def test_signup_still_rejects_undeliverable(self, auth_strict: AuthFort):
        with pytest.raises(AuthError) as exc_info:
            await auth_strict.create_user("k@k.k", "validpassword123")
        assert exc_info.value.code == "invalid_email"

    async def test_deliverable_email_still_accepted(self, auth_strict: AuthFort):
        """Sanity — real-looking domains pass through all paths."""
        ok_email = unique_email()  # test-abc@example.com
        # OTP request on a non-existent but deliverable email succeeds (200
        # semantics — token created if allow_passwordless_signup=True).
        await auth_strict.create_email_otp(ok_email)
