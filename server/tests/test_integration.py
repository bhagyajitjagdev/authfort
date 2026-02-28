"""Integration tests — full HTTP flow against real database."""

import uuid

import pytest
from httpx import AsyncClient

from authfort import AuthError, AuthFort

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    """Generate a unique email for each test to avoid conflicts."""
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


class TestSignup:
    async def test_signup_success(self, client: AsyncClient):
        email = unique_email()
        response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "name": "Test User",
        })

        assert response.status_code == 201
        data = response.json()
        assert data["user"]["email"] == email
        assert data["user"]["name"] == "Test User"
        assert data["user"]["email_verified"] is False
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]
        assert data["tokens"]["expires_in"] == 900

    async def test_signup_sets_cookies(self, client: AsyncClient):
        email = unique_email()
        response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })

        assert response.status_code == 201
        assert "access_token" in response.cookies
        assert "refresh_token" in response.cookies

    async def test_signup_duplicate_email(self, client: AsyncClient):
        email = unique_email()
        # First signup
        await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })

        # Second signup with same email
        response = await client.post("/auth/signup", json={
            "email": email,
            "password": "differentpassword",
        })

        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "user_exists"

    async def test_signup_missing_password(self, client: AsyncClient):
        response = await client.post("/auth/signup", json={
            "email": "test@example.com",
        })

        assert response.status_code == 422  # Pydantic validation error (password required)

    async def test_signup_invalid_email_no_at(self, client: AsyncClient):
        response = await client.post("/auth/signup", json={
            "email": "notanemail",
            "password": "testpassword123",
        })

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_email"

    async def test_signup_invalid_email_no_domain(self, client: AsyncClient):
        response = await client.post("/auth/signup", json={
            "email": "user@",
            "password": "testpassword123",
        })

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_email"

    async def test_signup_normalizes_email(self, client: AsyncClient):
        uid = uuid.uuid4().hex[:8]
        response = await client.post("/auth/signup", json={
            "email": f"  Test-{uid}@Example.COM  ",
            "password": "testpassword123",
        })

        assert response.status_code == 201
        assert response.json()["user"]["email"] == f"test-{uid}@example.com"


class TestLogin:
    async def test_login_success(self, client: AsyncClient):
        email = unique_email()
        # Create user first
        await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })

        # Login
        response = await client.post("/auth/login", json={
            "email": email,
            "password": "testpassword123",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == email
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]

    async def test_login_wrong_password(self, client: AsyncClient):
        email = unique_email()
        await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })

        response = await client.post("/auth/login", json={
            "email": email,
            "password": "wrongpassword",
        })

        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "invalid_credentials"

    async def test_login_nonexistent_email(self, client: AsyncClient):
        response = await client.post("/auth/login", json={
            "email": "nobody@example.com",
            "password": "testpassword123",
        })

        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "invalid_credentials"


class TestMe:
    async def test_me_with_bearer_token(self, client: AsyncClient):
        email = unique_email()
        signup_response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "name": "Bearer User",
        })
        access_token = signup_response.json()["tokens"]["access_token"]

        response = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {access_token}",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == email
        assert data["name"] == "Bearer User"

    async def test_me_without_token(self, client: AsyncClient):
        response = await client.get("/auth/me")

        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "token_missing"

    async def test_me_with_invalid_token(self, client: AsyncClient):
        response = await client.get("/auth/me", headers={
            "Authorization": "Bearer invalid.token.here",
        })

        assert response.status_code == 401


class TestRefresh:
    async def test_refresh_success(self, client: AsyncClient):
        email = unique_email()
        signup_response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        refresh_token = signup_response.json()["tokens"]["refresh_token"]

        response = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })

        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == email
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]
        # New refresh token should be different (rotation)
        assert data["tokens"]["refresh_token"] != refresh_token

    async def test_refresh_token_rotation_invalidates_old(self, client: AsyncClient):
        email = unique_email()
        signup_response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        old_refresh = signup_response.json()["tokens"]["refresh_token"]

        # Use the refresh token
        await client.post("/auth/refresh", json={
            "refresh_token": old_refresh,
        })

        # Try to use the old refresh token again — should fail (theft detection)
        response = await client.post("/auth/refresh", json={
            "refresh_token": old_refresh,
        })

        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "refresh_token_revoked"

    async def test_refresh_with_invalid_token(self, client: AsyncClient):
        response = await client.post("/auth/refresh", json={
            "refresh_token": "totally_invalid_token",
        })

        assert response.status_code == 401

    async def test_refresh_without_token(self, client: AsyncClient):
        response = await client.post("/auth/refresh")

        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "refresh_token_missing"

    async def test_refresh_preserves_session_id_in_response(self, client: AsyncClient):
        """session_id should remain stable across refresh token rotation."""
        email = unique_email()
        signup_response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        signup_data = signup_response.json()
        original_session_id = signup_data["user"]["session_id"]
        refresh_token = signup_data["tokens"]["refresh_token"]

        response = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert response.status_code == 200
        assert response.json()["user"]["session_id"] == original_session_id


class TestLogout:
    async def test_logout_success(self, client: AsyncClient):
        email = unique_email()
        signup_response = await client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        refresh_token = signup_response.json()["tokens"]["refresh_token"]

        response = await client.post("/auth/logout", json={
            "refresh_token": refresh_token,
        })

        assert response.status_code == 204

        # Refresh with the revoked token should fail
        refresh_response = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert refresh_response.status_code == 401

    async def test_logout_without_token(self, client: AsyncClient):
        """Logout without a token should still succeed (204) — just clears cookies."""
        response = await client.post("/auth/logout")
        assert response.status_code == 204


class TestFullFlow:
    async def test_signup_login_me_refresh_logout(self, client: AsyncClient):
        """Full end-to-end flow."""
        email = unique_email()

        # 1. Signup
        signup_res = await client.post("/auth/signup", json={
            "email": email,
            "password": "securepassword",
            "name": "E2E User",
        })
        assert signup_res.status_code == 201
        tokens = signup_res.json()["tokens"]

        # 2. Access /me with the access token
        me_res = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {tokens['access_token']}",
        })
        assert me_res.status_code == 200
        assert me_res.json()["email"] == email

        # 3. Login again (should work, returns new tokens)
        login_res = await client.post("/auth/login", json={
            "email": email,
            "password": "securepassword",
        })
        assert login_res.status_code == 200

        # 4. Refresh the token
        refresh_res = await client.post("/auth/refresh", json={
            "refresh_token": tokens["refresh_token"],
        })
        assert refresh_res.status_code == 200
        new_tokens = refresh_res.json()["tokens"]

        # 5. Use new access token
        me_res2 = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {new_tokens['access_token']}",
        })
        assert me_res2.status_code == 200

        # 6. Logout
        logout_res = await client.post("/auth/logout", json={
            "refresh_token": new_tokens["refresh_token"],
        })
        assert logout_res.status_code == 204

        # 7. Old refresh token should no longer work
        refresh_res2 = await client.post("/auth/refresh", json={
            "refresh_token": new_tokens["refresh_token"],
        })
        assert refresh_res2.status_code == 401


class TestRoles:
    async def _signup_and_get_token(self, client: AsyncClient) -> tuple[str, str, str]:
        """Helper: signup a user, return (email, password, access_token)."""
        email = unique_email()
        password = "testpassword123"
        res = await client.post("/auth/signup", json={
            "email": email,
            "password": password,
        })
        assert res.status_code == 201
        return email, password, res.json()["tokens"]["access_token"]

    async def test_require_role_returns_403_without_role(self, client: AsyncClient):
        """User without admin role gets 403 on role-protected endpoint."""
        _, _, token = await self._signup_and_get_token(client)

        res = await client.get("/test-admin", headers={
            "Authorization": f"Bearer {token}",
        })

        assert res.status_code == 403
        assert res.json()["detail"]["error"] == "insufficient_role"

    async def test_require_role_returns_200_with_role(self, client: AsyncClient, auth: AuthFort):
        """User with admin role can access role-protected endpoint."""
        email, password, _ = await self._signup_and_get_token(client)

        # Get user ID from /me
        login_res = await client.post("/auth/login", json={
            "email": email,
            "password": password,
        })
        user_id = login_res.json()["user"]["id"]

        # Add admin role (this bumps token_version, so we need a fresh token)
        await auth.add_role(uuid.UUID(user_id), "admin")

        # Re-login to get a token with updated token_version
        login_res2 = await client.post("/auth/login", json={
            "email": email,
            "password": password,
        })
        fresh_token = login_res2.json()["tokens"]["access_token"]

        res = await client.get("/test-admin", headers={
            "Authorization": f"Bearer {fresh_token}",
        })

        assert res.status_code == 200
        assert "admin" in res.json()["roles"]

    async def test_role_change_invalidates_old_token(self, client: AsyncClient, auth: AuthFort):
        """Adding a role bumps token_version, invalidating old tokens."""
        email, password, old_token = await self._signup_and_get_token(client)

        # Old token works on /auth/me
        me_res = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {old_token}",
        })
        assert me_res.status_code == 200
        user_id = me_res.json()["id"]

        # Add role (bumps token_version)
        await auth.add_role(uuid.UUID(user_id), "editor")

        # Old token should now be invalid (version mismatch)
        me_res2 = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {old_token}",
        })
        assert me_res2.status_code == 401
        assert me_res2.json()["detail"]["error"] == "token_version_mismatch"

    async def test_add_and_remove_role(self, client: AsyncClient, auth: AuthFort):
        """Roles can be added and removed."""
        email, password, _ = await self._signup_and_get_token(client)

        # Get user ID
        login_res = await client.post("/auth/login", json={
            "email": email,
            "password": password,
        })
        user_id = uuid.UUID(login_res.json()["user"]["id"])

        # Add roles
        await auth.add_role(user_id, "editor")
        await auth.add_role(user_id, "moderator")

        roles = await auth.get_roles(user_id)
        assert "editor" in roles
        assert "moderator" in roles

        # Remove one role
        await auth.remove_role(user_id, "editor")

        roles = await auth.get_roles(user_id)
        assert "editor" not in roles
        assert "moderator" in roles

    async def test_multiple_roles_or_logic(self, client: AsyncClient, auth: AuthFort):
        """require_role with a list uses OR logic — user needs any one of the roles."""
        email, password, _ = await self._signup_and_get_token(client)

        login_res = await client.post("/auth/login", json={
            "email": email,
            "password": password,
        })
        user_id = uuid.UUID(login_res.json()["user"]["id"])

        # Add only "editor" (not "admin")
        await auth.add_role(user_id, "editor")

        # Re-login for fresh token
        login_res2 = await client.post("/auth/login", json={
            "email": email,
            "password": password,
        })
        token = login_res2.json()["tokens"]["access_token"]

        # /test-content requires ["admin", "editor"] — editor should work (OR logic)
        res = await client.get("/test-content", headers={
            "Authorization": f"Bearer {token}",
        })

        assert res.status_code == 200
        assert "editor" in res.json()["roles"]


class TestSessionId:
    async def test_session_id_in_auth_response(self, auth: AuthFort):
        """Auth response should include session_id in user object."""
        email = unique_email()
        result = await auth.create_user(email, "password123")

        assert result.user.session_id is not None

    async def test_session_id_matches_a_session(self, auth: AuthFort):
        """session_id should correspond to an actual session."""
        email = unique_email()
        result = await auth.create_user(email, "password123")

        sessions = await auth.get_sessions(result.user.id)
        session_ids = [s.id for s in sessions]
        assert result.user.session_id in session_ids

    async def test_session_id_in_me_endpoint(self, client: AsyncClient):
        """GET /auth/me should include session_id."""
        email = unique_email()
        signup_res = await client.post("/auth/signup", json={
            "email": email,
            "password": "password123",
        })
        token = signup_res.json()["tokens"]["access_token"]

        me_res = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert me_res.status_code == 200
        assert me_res.json()["session_id"] is not None

    async def test_different_logins_have_different_session_ids(self, auth: AuthFort):
        """Each login should create a new session with a unique ID."""
        email = unique_email()
        result1 = await auth.create_user(email, "password123")
        result2 = await auth.login(email, "password123")

        assert result1.user.session_id != result2.user.session_id


class TestProgrammaticAPI:
    async def test_create_user(self, auth: AuthFort):
        """create_user() returns AuthResponse with valid user and tokens."""
        email = unique_email()
        result = await auth.create_user(email, "password123", name="Test User")

        assert result.user.email == email
        assert result.user.name == "Test User"
        assert result.tokens.access_token
        assert result.tokens.refresh_token

    async def test_login_programmatic(self, auth: AuthFort):
        """login() returns AuthResponse after creating a user."""
        email = unique_email()
        await auth.create_user(email, "password123")

        result = await auth.login(email, "password123")

        assert result.user.email == email
        assert result.tokens.access_token

    async def test_refresh_programmatic(self, auth: AuthFort):
        """refresh() returns new tokens with rotation."""
        email = unique_email()
        signup_result = await auth.create_user(email, "password123")
        old_refresh = signup_result.tokens.refresh_token

        result = await auth.refresh(old_refresh)

        assert result.user.email == email
        assert result.tokens.refresh_token != old_refresh

    async def test_logout_programmatic(self, auth: AuthFort):
        """logout() revokes the refresh token so it can't be reused."""
        email = unique_email()
        signup_result = await auth.create_user(email, "password123")

        await auth.logout(signup_result.tokens.refresh_token)

        with pytest.raises(AuthError, match="revoked"):
            await auth.refresh(signup_result.tokens.refresh_token)


class TestSignupDisabled:
    async def test_signup_disabled_returns_403(self, client_no_signup: AsyncClient):
        """POST /auth/signup returns 403 when allow_signup=False."""
        response = await client_no_signup.post("/auth/signup", json={
            "email": unique_email(),
            "password": "password123",
        })

        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "signup_disabled"

    async def test_create_user_works_when_signup_disabled(self, auth_no_signup: AuthFort):
        """Programmatic create_user() always works regardless of allow_signup."""
        email = unique_email()
        result = await auth_no_signup.create_user(email, "password123")

        assert result.user.email == email
        assert result.tokens.access_token

    async def test_login_still_works_when_signup_disabled(
        self, auth_no_signup: AuthFort, client_no_signup: AsyncClient,
    ):
        """Login endpoint works even when signup is disabled."""
        email = unique_email()
        await auth_no_signup.create_user(email, "password123")

        response = await client_no_signup.post("/auth/login", json={
            "email": email,
            "password": "password123",
        })

        assert response.status_code == 200
        assert response.json()["user"]["email"] == email


# ---------------------------------------------------------------------------
# Passwordless Endpoints
# ---------------------------------------------------------------------------


class TestMagicLinkEndpoints:
    async def test_request_magic_link_returns_200(self, client: AsyncClient):
        """POST /magic-link always returns 200 (enumeration-safe)."""
        response = await client.post("/auth/magic-link", json={
            "email": "nonexistent@example.com",
        })

        assert response.status_code == 200
        assert "message" in response.json()

    async def test_request_magic_link_for_existing_user(self, auth: AuthFort, client: AsyncClient):
        """POST /magic-link returns 200 for existing user."""
        email = unique_email()
        await auth.create_user(email, "password123")

        response = await client.post("/auth/magic-link", json={"email": email})

        assert response.status_code == 200

    async def test_verify_magic_link_success(self, auth: AuthFort, client: AsyncClient):
        """POST /magic-link/verify returns AuthResponse with tokens."""
        email = unique_email()
        await auth.create_user(email, "password123")
        token = await auth.create_magic_link_token(email)
        assert token is not None

        response = await client.post("/auth/magic-link/verify", json={"token": token})

        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == email
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]

    async def test_verify_magic_link_sets_cookies(self, auth: AuthFort, client: AsyncClient):
        """POST /magic-link/verify sets auth cookies."""
        email = unique_email()
        await auth.create_user(email, "password123")
        token = await auth.create_magic_link_token(email)

        response = await client.post("/auth/magic-link/verify", json={"token": token})

        assert response.status_code == 200
        assert "access_token" in response.cookies
        assert "refresh_token" in response.cookies

    async def test_verify_magic_link_invalid_token(self, client: AsyncClient):
        """POST /magic-link/verify returns 400 for invalid token."""
        response = await client.post("/auth/magic-link/verify", json={"token": "bogus"})

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_magic_link"


class TestOTPEndpoints:
    async def test_request_otp_returns_200(self, client: AsyncClient):
        """POST /otp always returns 200 (enumeration-safe)."""
        response = await client.post("/auth/otp", json={
            "email": "nonexistent@example.com",
        })

        assert response.status_code == 200
        assert "message" in response.json()

    async def test_request_otp_for_existing_user(self, auth: AuthFort, client: AsyncClient):
        """POST /otp returns 200 for existing user."""
        email = unique_email()
        await auth.create_user(email, "password123")

        response = await client.post("/auth/otp", json={"email": email})

        assert response.status_code == 200

    async def test_verify_otp_success(self, auth: AuthFort, client: AsyncClient):
        """POST /otp/verify returns AuthResponse with tokens."""
        email = unique_email()
        await auth.create_user(email, "password123")
        code = await auth.create_email_otp(email)
        assert code is not None

        response = await client.post("/auth/otp/verify", json={
            "email": email,
            "code": code,
        })

        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == email
        assert "access_token" in data["tokens"]

    async def test_verify_otp_sets_cookies(self, auth: AuthFort, client: AsyncClient):
        """POST /otp/verify sets auth cookies."""
        email = unique_email()
        await auth.create_user(email, "password123")
        code = await auth.create_email_otp(email)

        response = await client.post("/auth/otp/verify", json={
            "email": email,
            "code": code,
        })

        assert response.status_code == 200
        assert "access_token" in response.cookies

    async def test_verify_otp_invalid_code(self, auth: AuthFort, client: AsyncClient):
        """POST /otp/verify returns 400 for wrong code."""
        email = unique_email()
        await auth.create_user(email, "password123")
        await auth.create_email_otp(email)

        response = await client.post("/auth/otp/verify", json={
            "email": email,
            "code": "000000",
        })

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_otp"


class TestVerifyEmailEndpoint:
    async def test_verify_email_success(self, auth: AuthFort, client: AsyncClient):
        """POST /verify-email returns 200 on success."""
        email = unique_email()
        result = await auth.create_user(email, "password123")
        token = await auth.create_email_verification_token(result.user.id)
        assert token is not None

        response = await client.post("/auth/verify-email", json={"token": token})

        assert response.status_code == 200
        assert "message" in response.json()

    async def test_verify_email_invalid_token(self, client: AsyncClient):
        """POST /verify-email returns 400 for invalid token."""
        response = await client.post("/auth/verify-email", json={"token": "bogus"})

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_verification_token"
