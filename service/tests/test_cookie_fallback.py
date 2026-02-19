"""Tests for service cookie fallback in FastAPI dependency."""

import httpx
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from authfort_service import ServiceAuth
from conftest import create_test_token

pytestmark = pytest.mark.asyncio


def _patch_fetcher(monkeypatch, jwks_response):
    """Patch httpx.AsyncClient to return mock JWKS response."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks_response)

    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        if not isinstance(kwargs.get("transport"), ASGITransport):
            kwargs["transport"] = httpx.MockTransport(handler)
        original_init(self_client, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


class TestCookieFallback:
    async def test_cookie_fallback_reads_cookie(
        self, rsa_key_pair, test_kid, jwks_response, monkeypatch,
    ):
        """When no Bearer header, reads token from the configured cookie."""
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(
            jwks_url="http://test/.well-known/jwks.json",
            cookie_name="access_token",
        )
        token = create_test_token(private_pem, test_kid, email="cookie@example.com")

        app = FastAPI()

        @app.get("/profile")
        async def profile(user=Depends(sa.current_user)):
            return {"email": user.email}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ) as client:
            resp = await client.get(
                "/profile", cookies={"access_token": token},
            )
            assert resp.status_code == 200
            assert resp.json()["email"] == "cookie@example.com"

    async def test_bearer_takes_priority_over_cookie(
        self, rsa_key_pair, test_kid, jwks_response, monkeypatch,
    ):
        """When both Bearer header and cookie are present, Bearer wins."""
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(
            jwks_url="http://test/.well-known/jwks.json",
            cookie_name="access_token",
        )

        bearer_token = create_test_token(private_pem, test_kid, email="bearer@example.com")
        cookie_token = create_test_token(private_pem, test_kid, email="cookie@example.com")

        app = FastAPI()

        @app.get("/profile")
        async def profile(user=Depends(sa.current_user)):
            return {"email": user.email}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ) as client:
            resp = await client.get(
                "/profile",
                headers={"Authorization": f"Bearer {bearer_token}"},
                cookies={"access_token": cookie_token},
            )
            assert resp.status_code == 200
            assert resp.json()["email"] == "bearer@example.com"

    async def test_no_cookie_name_ignores_cookies(
        self, rsa_key_pair, test_kid, jwks_response, monkeypatch,
    ):
        """Without cookie_name configured, cookies are ignored and 401 is returned."""
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")
        token = create_test_token(private_pem, test_kid, email="test@example.com")

        app = FastAPI()

        @app.get("/profile")
        async def profile(user=Depends(sa.current_user)):
            return {"email": user.email}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ) as client:
            resp = await client.get(
                "/profile", cookies={"access_token": token},
            )
            assert resp.status_code == 401
