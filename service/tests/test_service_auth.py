"""Tests for ServiceAuth — main entry point, FastAPI integration."""

import httpx
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from authfort_service import ServiceAuth, TokenPayload, TokenVerificationError
from conftest import create_test_token

pytestmark = pytest.mark.asyncio


def _patch_fetcher(monkeypatch, jwks_response):
    """Patch httpx.AsyncClient to return mock JWKS response.

    Only patches clients that don't already have an ASGITransport
    (so the test's own ASGI test client isn't affected).
    """
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks_response)

    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        if not isinstance(kwargs.get("transport"), ASGITransport):
            kwargs["transport"] = httpx.MockTransport(handler)
        original_init(self_client, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


class TestServiceAuth:
    async def test_verify_token(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")
        token = create_test_token(private_pem, test_kid, email="test@example.com")
        payload = await sa.verify_token(token)

        assert isinstance(payload, TokenPayload)
        assert payload.email == "test@example.com"

    async def test_introspect_not_configured(self):
        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")
        with pytest.raises(RuntimeError, match="Introspection not configured"):
            await sa.introspect("token")

    async def test_current_user_dep(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")
        token = create_test_token(private_pem, test_kid, email="user@example.com", roles=["user"])

        app = FastAPI()

        @app.get("/profile")
        async def profile(user=Depends(sa.current_user)):
            return {"email": user.email, "roles": user.roles}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/profile", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            assert resp.json()["email"] == "user@example.com"

    async def test_require_role(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        private_pem, _ = rsa_key_pair

        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")

        app = FastAPI()

        @app.get("/admin")
        async def admin(user=Depends(sa.require_role("admin"))):
            return {"message": "admin access"}

        admin_token = create_test_token(private_pem, test_kid, roles=["admin"])
        user_token = create_test_token(private_pem, test_kid, roles=["user"])

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {admin_token}"})
            assert resp.status_code == 200

            resp = await client.get("/admin", headers={"Authorization": f"Bearer {user_token}"})
            assert resp.status_code == 403

    async def test_current_user_no_token(self, rsa_key_pair, test_kid, jwks_response, monkeypatch):
        _patch_fetcher(monkeypatch, jwks_response)
        sa = ServiceAuth(jwks_url="http://test/.well-known/jwks.json")

        app = FastAPI()

        @app.get("/profile")
        async def profile(user=Depends(sa.current_user)):
            return {"email": user.email}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/profile")
            assert resp.status_code == 401
