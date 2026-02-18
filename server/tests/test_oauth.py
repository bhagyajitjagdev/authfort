"""OAuth integration tests — full HTTP flow with mocked provider APIs."""

import uuid
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from authfort import AuthFort
from authfort.providers.base import OAuthUserInfo

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Fixtures: mock provider responses
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_google_user_info():
    """Returns a factory that creates mock Google OAuthUserInfo."""
    def _make(email=None, name="Google User", avatar="https://example.com/photo.jpg"):
        return OAuthUserInfo(
            provider="google",
            provider_account_id=f"google-{uuid.uuid4().hex[:8]}",
            email=email or unique_email(),
            email_verified=True,
            name=name,
            avatar_url=avatar,
            access_token="mock-google-access-token",
        )
    return _make


@pytest.fixture
def mock_github_user_info():
    """Returns a factory that creates mock GitHub OAuthUserInfo."""
    def _make(email=None, name="GitHub User", avatar="https://github.com/avatar.jpg"):
        return OAuthUserInfo(
            provider="github",
            provider_account_id=f"github-{uuid.uuid4().hex[:8]}",
            email=email or unique_email(),
            email_verified=True,
            name=name,
            avatar_url=avatar,
            access_token="mock-github-access-token",
        )
    return _make


def _get_state_from_redirect(response) -> str:
    """Extract the state parameter from a 302 redirect Location header."""
    location = response.headers["location"]
    parsed = urlparse(location)
    return parse_qs(parsed.query)["state"][0]


# ---------------------------------------------------------------------------
# Authorize endpoint tests
# ---------------------------------------------------------------------------

class TestOAuthAuthorize:
    async def test_google_authorize_redirects(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/google/authorize",
            follow_redirects=False,
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert "accounts.google.com" in location
        assert "client_id=test-google-id" in location
        assert "state=" in location
        assert "access_type=offline" in location

    async def test_github_authorize_redirects(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/github/authorize",
            follow_redirects=False,
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert "github.com/login/oauth/authorize" in location
        assert "client_id=test-github-id" in location
        assert "state=" in location

    async def test_unknown_provider_returns_404(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/unknown/authorize",
            follow_redirects=False,
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error"] == "unknown_provider"


# ---------------------------------------------------------------------------
# Callback validation tests
# ---------------------------------------------------------------------------

class TestOAuthCallback:
    async def test_missing_code_returns_400(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/google/callback",
            params={"state": "some-state"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "oauth_missing_params"

    async def test_missing_state_returns_400(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/google/callback",
            params={"code": "some-code"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "oauth_missing_params"

    async def test_provider_error_returns_400(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/google/callback",
            params={"error": "access_denied", "error_description": "User denied access"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "oauth_provider_error"

    async def test_invalid_state_returns_400(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/google/callback",
            params={"code": "some-code", "state": "invalid.jwt.token"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "oauth_state_invalid"

    async def test_unknown_provider_callback_returns_404(self, oauth_client: AsyncClient):
        response = await oauth_client.get(
            "/auth/oauth/unknown/callback",
            params={"code": "some-code", "state": "some-state"},
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Google full flow tests
# ---------------------------------------------------------------------------

class TestOAuthGoogleFlow:
    async def test_new_user_creation(self, oauth_client: AsyncClient, mock_google_user_info):
        """OAuth with a new email creates a new user."""
        user_info = mock_google_user_info()

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token", "token_type": "Bearer"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            # Step 1: Get state from authorize redirect
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize",
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            # Step 2: Hit callback
            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-auth-code", "state": state},
            )

        assert callback_res.status_code == 200
        data = callback_res.json()
        assert data["user"]["email"] == user_info.email
        assert data["user"]["email_verified"] is True
        assert data["user"]["name"] == "Google User"
        assert data["user"]["avatar_url"] == "https://example.com/photo.jpg"
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]

    async def test_sets_cookies(self, oauth_client: AsyncClient, mock_google_user_info):
        """OAuth callback sets auth cookies when cookie mode is enabled."""
        user_info = mock_google_user_info()

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token", "token_type": "Bearer"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        assert "access_token" in callback_res.cookies
        assert "refresh_token" in callback_res.cookies

    async def test_repeat_login_returns_same_user(self, oauth_client: AsyncClient):
        """Two OAuth logins with the same provider ID return the same user."""
        user_info = OAuthUserInfo(
            provider="google",
            provider_account_id="google-fixed-id",
            email=unique_email(),
            email_verified=True,
            name="Repeat User",
            access_token="mock-token",
        )

        user_ids = []
        for _ in range(2):
            with patch(
                "authfort.providers.google.GoogleProvider.exchange_code",
                new_callable=AsyncMock,
                return_value={"access_token": "mock-token"},
            ), patch(
                "authfort.providers.google.GoogleProvider.get_user_info",
                new_callable=AsyncMock,
                return_value=user_info,
            ):
                auth_res = await oauth_client.get(
                    "/auth/oauth/google/authorize", follow_redirects=False,
                )
                state = _get_state_from_redirect(auth_res)

                callback_res = await oauth_client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "mock-code", "state": state},
                )
                user_ids.append(callback_res.json()["user"]["id"])

        assert user_ids[0] == user_ids[1]

    async def test_oauth_user_can_access_me(self, oauth_client: AsyncClient, mock_google_user_info):
        """After OAuth login, the issued access token works on /auth/me."""
        user_info = mock_google_user_info()

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        access_token = callback_res.json()["tokens"]["access_token"]
        me_res = await oauth_client.get(
            "/auth/me", headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_res.status_code == 200
        assert me_res.json()["email"] == user_info.email


# ---------------------------------------------------------------------------
# GitHub full flow tests
# ---------------------------------------------------------------------------

class TestOAuthGitHubFlow:
    async def test_new_user_creation(self, oauth_client: AsyncClient, mock_github_user_info):
        """GitHub OAuth creates a new user."""
        user_info = mock_github_user_info()

        with patch(
            "authfort.providers.github.GitHubProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-github-token", "token_type": "Bearer"},
        ), patch(
            "authfort.providers.github.GitHubProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/github/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/github/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        data = callback_res.json()
        assert data["user"]["email"] == user_info.email
        assert data["user"]["name"] == "GitHub User"

    async def test_no_email_returns_error(self, oauth_client: AsyncClient):
        """GitHub OAuth raises error when no email can be retrieved."""
        from authfort.core.auth import AuthError

        with patch(
            "authfort.providers.github.GitHubProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.github.GitHubProvider.get_user_info",
            new_callable=AsyncMock,
            side_effect=AuthError(
                "Could not retrieve email from GitHub",
                code="oauth_no_email",
                status_code=400,
            ),
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/github/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/github/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 400
        assert callback_res.json()["detail"]["error"] == "oauth_no_email"


# ---------------------------------------------------------------------------
# Auto-linking tests
# ---------------------------------------------------------------------------

class TestOAuthAutoLinking:
    async def test_email_signup_then_google_oauth_links_accounts(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """User signs up with email, then logs in with Google using the same
        email — should link to the same user, not create a new one."""
        email = unique_email()

        # Step 1: Email signup
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
            "name": "Email User",
        })
        assert signup_res.status_code == 201
        email_user_id = signup_res.json()["user"]["id"]

        # Step 2: Google OAuth with same email
        user_info = mock_google_user_info(email=email, name="Google User")

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        oauth_user_id = callback_res.json()["user"]["id"]

        # Same user
        assert oauth_user_id == email_user_id

    async def test_oauth_updates_email_verified(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """If email was unverified from signup, OAuth login with verified email
        updates email_verified to True."""
        email = unique_email()

        # Signup — email_verified is False by default
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        assert signup_res.status_code == 201
        assert signup_res.json()["user"]["email_verified"] is False

        # Google OAuth with same email (email_verified=True)
        user_info = mock_google_user_info(email=email)

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        assert callback_res.json()["user"]["email_verified"] is True

    async def test_oauth_fills_missing_profile_fields(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """OAuth login fills in name and avatar_url if the user doesn't have them."""
        email = unique_email()

        # Signup without name
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })
        assert signup_res.status_code == 201
        assert signup_res.json()["user"]["name"] is None

        # Google OAuth fills in name + avatar
        user_info = mock_google_user_info(email=email, name="From Google", avatar="https://photo.url")

        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            "authfort.providers.google.GoogleProvider.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

        assert callback_res.status_code == 200
        user = callback_res.json()["user"]
        assert user["name"] == "From Google"
        assert user["avatar_url"] == "https://photo.url"


# ---------------------------------------------------------------------------
# Cross-account scenario tests
# ---------------------------------------------------------------------------

class TestCrossAccountScenarios:
    """Tests for all possible account type interactions."""

    async def _oauth_login(self, oauth_client, provider, user_info, patch_module):
        """Helper: complete an OAuth login flow with mocked provider."""
        with patch(
            f"authfort.providers.{patch_module}.{provider}.exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "mock-token"},
        ), patch(
            f"authfort.providers.{patch_module}.{provider}.get_user_info",
            new_callable=AsyncMock,
            return_value=user_info,
        ):
            auth_res = await oauth_client.get(
                f"/auth/oauth/{user_info.provider}/authorize",
                follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            return await oauth_client.get(
                f"/auth/oauth/{user_info.provider}/callback",
                params={"code": "mock-code", "state": state},
            )

    # --- OAuth user tries manual login ---

    async def test_oauth_user_manual_login_returns_oauth_account_error(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """OAuth-only user trying manual login gets 'oauth_account' error with providers."""
        email = unique_email()
        user_info = mock_google_user_info(email=email)

        # Create user via Google OAuth
        res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert res.status_code == 200

        # Try manual login — should get specific error
        login_res = await oauth_client.post("/auth/login", json={
            "email": email,
            "password": "anypassword",
        })

        assert login_res.status_code == 401
        detail = login_res.json()["detail"]
        assert detail["error"] == "oauth_account"
        assert detail["message"] == "This account uses social login"
        assert "google" in detail["providers"]

    async def test_oauth_user_manual_login_shows_multiple_providers(
        self, oauth_client: AsyncClient,
    ):
        """User with both Google and GitHub gets both providers in error."""
        email = unique_email()
        google_id = f"google-{uuid.uuid4().hex[:8]}"
        github_id = f"github-{uuid.uuid4().hex[:8]}"

        google_info = OAuthUserInfo(
            provider="google", provider_account_id=google_id,
            email=email, email_verified=True, name="User",
            access_token="mock-token",
        )
        github_info = OAuthUserInfo(
            provider="github", provider_account_id=github_id,
            email=email, email_verified=True, name="User",
            access_token="mock-token",
        )

        # Login via Google first
        res = await self._oauth_login(oauth_client, "GoogleProvider", google_info, "google")
        assert res.status_code == 200

        # Then link GitHub
        res = await self._oauth_login(oauth_client, "GitHubProvider", github_info, "github")
        assert res.status_code == 200

        # Try manual login
        login_res = await oauth_client.post("/auth/login", json={
            "email": email,
            "password": "anypassword",
        })

        assert login_res.status_code == 401
        detail = login_res.json()["detail"]
        assert detail["error"] == "oauth_account"
        assert "google" in detail["providers"]
        assert "github" in detail["providers"]

    # --- OAuth user tries manual signup ---

    async def test_oauth_user_manual_signup_returns_409(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """OAuth user trying to signup manually gets 'user_exists' 409."""
        email = unique_email()
        user_info = mock_google_user_info(email=email)

        # Create via Google OAuth
        res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert res.status_code == 200

        # Try manual signup — should be blocked
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email,
            "password": "testpassword123",
        })

        assert signup_res.status_code == 409
        assert signup_res.json()["detail"]["error"] == "user_exists"

    # --- Manual user tries OAuth ---

    async def test_manual_user_google_oauth_links_and_works(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """Manual user logging in with Google auto-links and still works with password."""
        email = unique_email()
        password = "testpassword123"

        # Manual signup
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email, "password": password,
        })
        assert signup_res.status_code == 201
        user_id = signup_res.json()["user"]["id"]

        # Google OAuth with same email
        user_info = mock_google_user_info(email=email)
        oauth_res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert oauth_res.status_code == 200
        assert oauth_res.json()["user"]["id"] == user_id  # same user

        # Manual login still works
        login_res = await oauth_client.post("/auth/login", json={
            "email": email, "password": password,
        })
        assert login_res.status_code == 200
        assert login_res.json()["user"]["id"] == user_id

    async def test_manual_user_github_oauth_links_and_works(
        self, oauth_client: AsyncClient, mock_github_user_info,
    ):
        """Manual user logging in with GitHub auto-links and still works with password."""
        email = unique_email()
        password = "testpassword123"

        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email, "password": password,
        })
        assert signup_res.status_code == 201
        user_id = signup_res.json()["user"]["id"]

        user_info = mock_github_user_info(email=email)
        oauth_res = await self._oauth_login(oauth_client, "GitHubProvider", user_info, "github")
        assert oauth_res.status_code == 200
        assert oauth_res.json()["user"]["id"] == user_id

        # Manual login still works
        login_res = await oauth_client.post("/auth/login", json={
            "email": email, "password": password,
        })
        assert login_res.status_code == 200

    # --- Cross-OAuth provider linking ---

    async def test_google_user_github_oauth_links_same_account(
        self, oauth_client: AsyncClient,
    ):
        """Google user logging in with GitHub (same email) links to same account."""
        email = unique_email()
        google_id = f"google-{uuid.uuid4().hex[:8]}"
        github_id = f"github-{uuid.uuid4().hex[:8]}"

        google_info = OAuthUserInfo(
            provider="google", provider_account_id=google_id,
            email=email, email_verified=True, name="User",
            access_token="mock-token",
        )
        github_info = OAuthUserInfo(
            provider="github", provider_account_id=github_id,
            email=email, email_verified=True, name="User",
            access_token="mock-token",
        )

        # Login via Google
        google_res = await self._oauth_login(oauth_client, "GoogleProvider", google_info, "google")
        assert google_res.status_code == 200
        user_id = google_res.json()["user"]["id"]

        # Login via GitHub (same email)
        github_res = await self._oauth_login(oauth_client, "GitHubProvider", github_info, "github")
        assert github_res.status_code == 200
        assert github_res.json()["user"]["id"] == user_id  # same user

    async def test_different_emails_creates_separate_users(
        self, oauth_client: AsyncClient,
    ):
        """OAuth logins with different emails create separate users (no linking)."""
        google_info = OAuthUserInfo(
            provider="google", provider_account_id="google-abc",
            email=unique_email(), email_verified=True, name="Google User",
            access_token="mock-token",
        )
        github_info = OAuthUserInfo(
            provider="github", provider_account_id="github-xyz",
            email=unique_email(), email_verified=True, name="GitHub User",
            access_token="mock-token",
        )

        google_res = await self._oauth_login(oauth_client, "GoogleProvider", google_info, "google")
        github_res = await self._oauth_login(oauth_client, "GitHubProvider", github_info, "github")

        assert google_res.status_code == 200
        assert github_res.status_code == 200
        assert google_res.json()["user"]["id"] != github_res.json()["user"]["id"]

    # --- OAuth user can use refresh/logout ---

    async def test_oauth_user_can_refresh_token(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """OAuth user's refresh token works normally."""
        user_info = mock_google_user_info()
        oauth_res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert oauth_res.status_code == 200

        refresh_token = oauth_res.json()["tokens"]["refresh_token"]
        refresh_res = await oauth_client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert refresh_res.status_code == 200
        assert refresh_res.json()["tokens"]["refresh_token"] != refresh_token  # rotation

    async def test_oauth_user_can_logout(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """OAuth user can logout (revoke refresh token)."""
        user_info = mock_google_user_info()
        oauth_res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert oauth_res.status_code == 200

        refresh_token = oauth_res.json()["tokens"]["refresh_token"]
        logout_res = await oauth_client.post("/auth/logout", json={
            "refresh_token": refresh_token,
        })
        assert logout_res.status_code == 204

        # Refresh should fail after logout
        refresh_res = await oauth_client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert refresh_res.status_code == 401

    # --- OAuth code exchange failure ---

    async def test_oauth_code_exchange_failure(self, oauth_client: AsyncClient):
        """If provider code exchange fails, returns proper error."""
        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            side_effect=Exception("Connection refused"),
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "bad-code", "state": state},
            )

        assert callback_res.status_code == 400
        assert callback_res.json()["detail"]["error"] == "oauth_exchange_failed"

    async def test_oauth_no_access_token_in_response(self, oauth_client: AsyncClient):
        """If provider returns no access_token, returns proper error."""
        with patch(
            "authfort.providers.google.GoogleProvider.exchange_code",
            new_callable=AsyncMock,
            return_value={"error": "invalid_grant"},  # no access_token
        ):
            auth_res = await oauth_client.get(
                "/auth/oauth/google/authorize", follow_redirects=False,
            )
            state = _get_state_from_redirect(auth_res)

            callback_res = await oauth_client.get(
                "/auth/oauth/google/callback",
                params={"code": "expired-code", "state": state},
            )

        assert callback_res.status_code == 400
        assert callback_res.json()["detail"]["error"] == "oauth_exchange_failed"

    # --- Profile preservation ---

    async def test_oauth_does_not_overwrite_existing_name(
        self, oauth_client: AsyncClient, mock_google_user_info,
    ):
        """If user already has a name, OAuth login doesn't overwrite it."""
        email = unique_email()

        # Signup with a name
        signup_res = await oauth_client.post("/auth/signup", json={
            "email": email, "password": "testpassword123", "name": "Original Name",
        })
        assert signup_res.status_code == 201

        # Google OAuth with different name
        user_info = mock_google_user_info(email=email, name="Google Name")
        oauth_res = await self._oauth_login(oauth_client, "GoogleProvider", user_info, "google")
        assert oauth_res.status_code == 200
        assert oauth_res.json()["user"]["name"] == "Original Name"  # not overwritten
