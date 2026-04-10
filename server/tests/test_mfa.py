"""Tests for TOTP MFA — setup, login flow, backup codes, disable, admin override."""

import time
import uuid
from urllib.parse import unquote

import pyotp
import pytest

from authfort import AuthFort, AuthError, CookieConfig

pytestmark = pytest.mark.asyncio


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _next_code(secret: str) -> str:
    """Return a valid TOTP code from the NEXT 30s window.

    After enable_mfa_confirm() stores the current window's code as
    last_used_code, any subsequent call that uses totp.now() in the same
    window triggers replay protection. Using the next window's code avoids
    this while still being accepted by verify(valid_window=1).
    """
    return pyotp.TOTP(secret).at(time.time() + 30)


async def _create_user(auth: AuthFort, email=None, password="testpassword123"):
    email = email or unique_email()
    result = await auth.create_user(email, password)
    return email, result.user.id


async def _enable_mfa(auth: AuthFort, user_id: uuid.UUID) -> tuple[str, list[str]]:
    """Enable MFA and return (totp_secret, backup_codes).

    enable_mfa_confirm stores the current window's code as last_used_code.
    Callers that need to use TOTP after this should call _next_code(secret)
    to get the next window's code.
    """
    setup = await auth.enable_mfa_init(user_id)
    totp = pyotp.TOTP(setup.secret)
    backup_codes = await auth.enable_mfa_confirm(user_id, totp.now())
    return setup.secret, backup_codes


# ---------------------------------------------------------------------------
# Unit: core/mfa.py
# ---------------------------------------------------------------------------

class TestGenerateBackupCodes:
    def test_returns_correct_count(self):
        from authfort.core.mfa import generate_backup_codes
        codes = generate_backup_codes(10)
        assert len(codes) == 10

    def test_format_xxxxx_xxxxx(self):
        from authfort.core.mfa import generate_backup_codes
        for code in generate_backup_codes(5):
            parts = code.split("-")
            assert len(parts) == 2
            assert len(parts[0]) == 5
            assert len(parts[1]) == 5

    def test_codes_are_unique(self):
        from authfort.core.mfa import generate_backup_codes
        codes = generate_backup_codes(10)
        assert len(set(codes)) == 10


class TestHashAndVerifyBackupCode:
    def test_hash_is_hex_sha256(self):
        from authfort.core.mfa import hash_backup_code
        h = hash_backup_code("abcde-fghij")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_same_code_same_hash(self):
        from authfort.core.mfa import hash_backup_code
        assert hash_backup_code("abcde-fghij") == hash_backup_code("abcde-fghij")

    def test_case_insensitive(self):
        from authfort.core.mfa import hash_backup_code
        assert hash_backup_code("ABCDE-FGHIJ") == hash_backup_code("abcde-fghij")

    def test_verify_match(self):
        from authfort.core.mfa import generate_backup_codes, hash_backup_code, verify_backup_code
        codes = generate_backup_codes(5)
        hashes = [hash_backup_code(c) for c in codes]
        assert verify_backup_code(codes[0], hashes) == hashes[0]

    def test_verify_no_match(self):
        from authfort.core.mfa import hash_backup_code, verify_backup_code
        hashes = [hash_backup_code("aaaaa-bbbbb")]
        assert verify_backup_code("zzzzz-zzzzz", hashes) is None

    def test_verify_empty_list(self):
        from authfort.core.mfa import verify_backup_code
        assert verify_backup_code("aaaaa-bbbbb", []) is None


class TestVerifyTOTPCode:
    def test_valid_code_accepted(self):
        from authfort.core.mfa import verify_totp_code
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        assert verify_totp_code(secret, totp.now(), last_used_at=None, last_used_code=None)

    def test_wrong_code_rejected(self):
        from authfort.core.mfa import verify_totp_code
        secret = pyotp.random_base32()
        assert not verify_totp_code(secret, "000000", last_used_at=None, last_used_code=None)

    def test_replay_rejected_same_window(self):
        from authfort.core.mfa import verify_totp_code
        from datetime import UTC, datetime
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        # Replay within same 30s window rejected
        now = datetime.now(UTC)
        assert not verify_totp_code(secret, code, last_used_at=now, last_used_code=code)

    def test_same_code_different_window_allowed(self):
        from authfort.core.mfa import verify_totp_code
        from datetime import UTC, datetime, timedelta
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        # last_used_at in a previous window (61s ago) — same code is allowed
        old_window_time = datetime.now(UTC) - timedelta(seconds=61)
        assert verify_totp_code(secret, code, last_used_at=old_window_time, last_used_code=code)

    def test_different_code_same_window_allowed(self):
        from authfort.core.mfa import verify_totp_code
        from datetime import UTC, datetime
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        now = datetime.now(UTC)
        # Different stored code, same window — not a replay
        assert verify_totp_code(
            secret, current_code, last_used_at=now, last_used_code="999999",
        )

    def test_next_window_code_accepted(self):
        from authfort.core.mfa import verify_totp_code
        secret = pyotp.random_base32()
        next_code = pyotp.TOTP(secret).at(time.time() + 30)
        # Next window code passes with valid_window=1
        assert verify_totp_code(secret, next_code, last_used_at=None, last_used_code=None)


# ---------------------------------------------------------------------------
# Integration: AuthFort instance methods
# ---------------------------------------------------------------------------

class TestEnableMFAInit:
    async def test_returns_secret_and_qr_uri(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        setup = await auth.enable_mfa_init(user_id)

        assert setup.secret
        assert setup.qr_uri.startswith("otpauth://totp/")
        assert len(setup.secret) >= 16

    async def test_qr_uri_contains_email(self, auth: AuthFort):
        email, user_id = await _create_user(auth)
        setup = await auth.enable_mfa_init(user_id)
        # pyotp URL-encodes '@' as '%40' in the otpauth URI
        assert email in unquote(setup.qr_uri)

    async def test_user_not_found_raises(self, auth: AuthFort):
        with pytest.raises(AuthError, match="User not found"):
            await auth.enable_mfa_init(uuid.uuid4())

    async def test_already_enabled_raises(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)

        with pytest.raises(AuthError, match="already enabled"):
            await auth.enable_mfa_init(user_id)

    async def test_reinit_replaces_old_secret(self, auth: AuthFort):
        """If init is called again before confirm, old secret is replaced."""
        _, user_id = await _create_user(auth)
        setup1 = await auth.enable_mfa_init(user_id)
        setup2 = await auth.enable_mfa_init(user_id)
        assert setup1.secret != setup2.secret


class TestEnableMFAConfirm:
    async def test_returns_backup_codes(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        setup = await auth.enable_mfa_init(user_id)
        totp = pyotp.TOTP(setup.secret)
        backup_codes = await auth.enable_mfa_confirm(user_id, totp.now())

        assert len(backup_codes) == 10
        for code in backup_codes:
            parts = code.split("-")
            assert len(parts) == 2

    async def test_mfa_is_now_enabled(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)
        status = await auth.get_mfa_status(user_id)
        assert status.enabled is True

    async def test_wrong_code_rejected(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await auth.enable_mfa_init(user_id)

        with pytest.raises(AuthError, match="Invalid"):
            await auth.enable_mfa_confirm(user_id, "000000")

    async def test_setup_not_initiated_raises(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        # No init called — no UserMFA row exists
        with pytest.raises(AuthError):
            await auth.enable_mfa_confirm(user_id, "123456")

    async def test_mfa_enabled_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("mfa_enabled", lambda e: events_received.append(e))

        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id


class TestLoginWithMFA:
    async def test_login_returns_mfa_challenge(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        await _enable_mfa(auth, user_id)

        result = await auth.login(email, "pass1234!")

        from authfort.core.schemas import MFAChallenge
        assert isinstance(result, MFAChallenge)
        assert result.mfa_required is True
        assert result.mfa_token
        assert result.expires_in == 300

    async def test_login_without_mfa_returns_auth_response(self, auth: AuthFort):
        email, _ = await _create_user(auth, password="pass1234!")

        from authfort.core.schemas import AuthResponse
        result = await auth.login(email, "pass1234!")
        assert isinstance(result, AuthResponse)
        assert result.tokens.access_token


class TestCompleteMFALogin:
    async def test_complete_with_valid_totp(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        # Use next window code — confirm stored current window's code as last_used
        result = await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))

        assert result.user.email == email
        assert result.tokens.access_token

    async def test_complete_with_backup_code(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        _, backup_codes = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, backup_codes[0])

        assert result.user.email == email
        assert result.tokens.access_token

    async def test_backup_code_is_single_use(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        _, backup_codes = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        await auth.complete_mfa_login(challenge.mfa_token, backup_codes[0])

        # Login again and try same backup code — must be rejected
        challenge2 = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError, match="Invalid"):
            await auth.complete_mfa_login(challenge2.mfa_token, backup_codes[0])

    async def test_wrong_totp_code_rejected(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError, match="Invalid"):
            await auth.complete_mfa_login(challenge.mfa_token, "000000")

    async def test_invalid_mfa_token_rejected(self, auth: AuthFort):
        with pytest.raises(AuthError, match="Invalid MFA token"):
            await auth.complete_mfa_login("totally.bogus.token", "123456")

    async def test_replay_totp_code_rejected(self, auth: AuthFort):
        """Same TOTP code submitted twice in the same 30s window is rejected."""
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        # Use next-window code to avoid collision with the confirm code
        code = _next_code(secret)

        # First login completes successfully
        challenge = await auth.login(email, "pass1234!")
        await auth.complete_mfa_login(challenge.mfa_token, code)

        # Second login — same code in same window → replay rejected
        challenge2 = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError, match="Invalid"):
            await auth.complete_mfa_login(challenge2.mfa_token, code)

    async def test_mfa_login_event_fired(self, auth: AuthFort):
        mfa_login_events = []
        auth.add_hook("mfa_login", lambda e: mfa_login_events.append(e))

        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))

        assert len(mfa_login_events) == 1
        assert mfa_login_events[0].user_id == user_id

    async def test_backup_code_used_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("backup_code_used", lambda e: events_received.append(e))

        email, user_id = await _create_user(auth, password="pass1234!")
        _, backup_codes = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        await auth.complete_mfa_login(challenge.mfa_token, backup_codes[0])

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id

    async def test_mfa_failed_event_on_wrong_code(self, auth: AuthFort):
        failed_events = []
        auth.add_hook("mfa_failed", lambda e: failed_events.append(e))

        email, user_id = await _create_user(auth, password="pass1234!")
        await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError):
            await auth.complete_mfa_login(challenge.mfa_token, "000000")

        assert len(failed_events) == 1
        assert failed_events[0].user_id == user_id


class TestMFAClaimInJWT:
    async def test_mfa_enabled_claim_true_after_setup(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))

        import jwt
        payload = jwt.decode(
            result.tokens.access_token,
            options={"verify_signature": False},
        )
        assert payload["mfa_enabled"] is True

    async def test_mfa_enabled_claim_false_for_regular_user(self, auth: AuthFort):
        email, _ = await _create_user(auth, password="pass1234!")
        result = await auth.login(email, "pass1234!")

        import jwt
        payload = jwt.decode(
            result.tokens.access_token,
            options={"verify_signature": False},
        )
        assert payload["mfa_enabled"] is False

    async def test_user_response_mfa_enabled_field(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        result = await auth.complete_mfa_login(challenge.mfa_token, _next_code(secret))

        assert result.user.mfa_enabled is True


class TestDisableMFA:
    async def test_disable_with_valid_totp(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        await auth.disable_mfa(user_id, _next_code(secret))

        status = await auth.get_mfa_status(user_id)
        assert status.enabled is False

    async def test_disable_with_backup_code(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        _, backup_codes = await _enable_mfa(auth, user_id)

        await auth.disable_mfa(user_id, backup_codes[0])

        status = await auth.get_mfa_status(user_id)
        assert status.enabled is False

    async def test_backup_codes_removed_after_disable(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        # Verify codes exist before disable
        status_before = await auth.get_mfa_status(user_id)
        assert status_before.backup_codes_remaining == 10

        await auth.disable_mfa(user_id, _next_code(secret))

        # After disable, status reflects not enabled
        status_after = await auth.get_mfa_status(user_id)
        assert status_after.enabled is False
        assert status_after.backup_codes_remaining == 0

    async def test_wrong_code_rejected(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)

        with pytest.raises(AuthError, match="Invalid"):
            await auth.disable_mfa(user_id, "000000")

    async def test_not_enabled_raises(self, auth: AuthFort):
        _, user_id = await _create_user(auth)

        with pytest.raises(AuthError):
            await auth.disable_mfa(user_id, "123456")

    async def test_mfa_disabled_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("mfa_disabled", lambda e: events_received.append(e))

        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        await auth.disable_mfa(user_id, _next_code(secret))

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id

    async def test_login_returns_tokens_after_disable(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, _ = await _enable_mfa(auth, user_id)

        await auth.disable_mfa(user_id, _next_code(secret))

        from authfort.core.schemas import AuthResponse
        result = await auth.login(email, "pass1234!")
        assert isinstance(result, AuthResponse)


class TestAdminDisableMFA:
    async def test_disables_without_code(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)

        await auth.admin_disable_mfa(user_id)

        status = await auth.get_mfa_status(user_id)
        assert status.enabled is False

    async def test_not_enabled_raises(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        with pytest.raises(AuthError):
            await auth.admin_disable_mfa(user_id)

    async def test_mfa_disabled_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("mfa_disabled", lambda e: events_received.append(e))

        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)
        await auth.admin_disable_mfa(user_id)

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id


class TestRegenerateBackupCodes:
    async def test_returns_new_codes(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        secret, old_codes = await _enable_mfa(auth, user_id)

        new_codes = await auth.regenerate_backup_codes(user_id, _next_code(secret))

        assert len(new_codes) == 10
        assert set(new_codes) != set(old_codes)

    async def test_old_codes_invalidated(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        secret, old_codes = await _enable_mfa(auth, user_id)

        new_code = _next_code(secret)
        await auth.regenerate_backup_codes(user_id, new_code)

        # Old backup code should no longer work
        challenge = await auth.login(email, "pass1234!")
        with pytest.raises(AuthError, match="Invalid"):
            await auth.complete_mfa_login(challenge.mfa_token, old_codes[0])

    async def test_wrong_totp_code_rejected(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)

        with pytest.raises(AuthError, match="Invalid"):
            await auth.regenerate_backup_codes(user_id, "000000")

    async def test_mfa_not_enabled_raises(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        with pytest.raises(AuthError):
            await auth.regenerate_backup_codes(user_id, "123456")

    async def test_backup_codes_regenerated_event_fired(self, auth: AuthFort):
        events_received = []
        auth.add_hook("backup_codes_regenerated", lambda e: events_received.append(e))

        _, user_id = await _create_user(auth)
        secret, _ = await _enable_mfa(auth, user_id)

        await auth.regenerate_backup_codes(user_id, _next_code(secret))

        assert len(events_received) == 1
        assert events_received[0].user_id == user_id


class TestGetMFAStatus:
    async def test_not_enabled_returns_false(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        status = await auth.get_mfa_status(user_id)
        assert status.enabled is False
        assert status.backup_codes_remaining == 0

    async def test_enabled_returns_true_with_codes(self, auth: AuthFort):
        _, user_id = await _create_user(auth)
        await _enable_mfa(auth, user_id)
        status = await auth.get_mfa_status(user_id)
        assert status.enabled is True
        assert status.backup_codes_remaining == 10

    async def test_backup_code_count_decreases(self, auth: AuthFort):
        email, user_id = await _create_user(auth, password="pass1234!")
        _, backup_codes = await _enable_mfa(auth, user_id)

        challenge = await auth.login(email, "pass1234!")
        await auth.complete_mfa_login(challenge.mfa_token, backup_codes[0])

        status = await auth.get_mfa_status(user_id)
        assert status.backup_codes_remaining == 9


# ---------------------------------------------------------------------------
# HTTP: FastAPI endpoints via client fixture
# ---------------------------------------------------------------------------

class TestMFAHTTPEndpoints:
    async def _signup_and_login(self, client, email=None, password="testpass123!"):
        email = email or unique_email()
        r = await client.post("/auth/signup", json={"email": email, "password": password})
        assert r.status_code in (200, 201)
        return email, r.cookies

    async def _enable_mfa_http(self, client, cookies) -> tuple[str, list[str], object]:
        """Init + confirm MFA over HTTP. Returns (secret, backup_codes, updated_cookies)."""
        r = await client.post("/auth/mfa/init", cookies=cookies)
        assert r.status_code == 200
        secret = r.json()["secret"]
        totp = pyotp.TOTP(secret)
        r2 = await client.post("/auth/mfa/confirm", json={"code": totp.now()}, cookies=r.cookies or cookies)
        assert r2.status_code == 200
        return secret, r2.json(), r2.cookies or cookies

    async def test_mfa_init_requires_auth(self, client):
        r = await client.post("/auth/mfa/init")
        assert r.status_code == 401

    async def test_mfa_status_requires_auth(self, client):
        r = await client.get("/auth/mfa/status")
        assert r.status_code == 401

    async def test_mfa_init_returns_setup(self, client):
        _, cookies = await self._signup_and_login(client)
        r = await client.post("/auth/mfa/init", cookies=cookies)
        assert r.status_code == 200
        data = r.json()
        assert "secret" in data
        assert data["qr_uri"].startswith("otpauth://totp/")

    async def test_mfa_confirm_enables_mfa(self, client):
        _, cookies = await self._signup_and_login(client)

        r = await client.post("/auth/mfa/init", cookies=cookies)
        secret = r.json()["secret"]
        totp = pyotp.TOTP(secret)

        r = await client.post("/auth/mfa/confirm", json={"code": totp.now()}, cookies=cookies)
        assert r.status_code == 200
        backup_codes = r.json()
        assert len(backup_codes) == 10

    async def test_mfa_confirm_wrong_code(self, client):
        _, cookies = await self._signup_and_login(client)
        await client.post("/auth/mfa/init", cookies=cookies)

        r = await client.post("/auth/mfa/confirm", json={"code": "000000"}, cookies=cookies)
        assert r.status_code == 400

    async def test_login_returns_mfa_challenge_when_enabled(self, client):
        email, cookies = await self._signup_and_login(client, password="pass1234!")
        await self._enable_mfa_http(client, cookies)

        r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
        assert r.status_code == 200
        data = r.json()
        assert data["mfa_required"] is True
        assert "mfa_token" in data
        assert "tokens" not in data

    async def test_mfa_verify_completes_login(self, client):
        email, cookies = await self._signup_and_login(client, password="pass1234!")
        secret, _, updated_cookies = await self._enable_mfa_http(client, cookies)

        r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
        mfa_token = r.json()["mfa_token"]

        r = await client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": _next_code(secret)},
        )
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data["tokens"]
        assert data["user"]["mfa_enabled"] is True

    async def test_mfa_verify_with_backup_code(self, client):
        email, cookies = await self._signup_and_login(client, password="pass1234!")
        _, backup_codes, _ = await self._enable_mfa_http(client, cookies)

        r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
        mfa_token = r.json()["mfa_token"]

        r = await client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": backup_codes[0]},
        )
        assert r.status_code == 200

    async def test_mfa_verify_wrong_code(self, client):
        email, cookies = await self._signup_and_login(client, password="pass1234!")
        await self._enable_mfa_http(client, cookies)

        r = await client.post("/auth/login", json={"email": email, "password": "pass1234!"})
        mfa_token = r.json()["mfa_token"]

        r = await client.post(
            "/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": "000000"},
        )
        assert r.status_code == 401

    async def test_mfa_status_endpoint(self, client):
        _, cookies = await self._signup_and_login(client)

        r = await client.get("/auth/mfa/status", cookies=cookies)
        assert r.status_code == 200
        data = r.json()
        assert data["enabled"] is False
        assert data["backup_codes_remaining"] == 0

    async def test_mfa_disable_endpoint(self, client):
        _, cookies = await self._signup_and_login(client)
        secret, _, updated_cookies = await self._enable_mfa_http(client, cookies)

        r = await client.post(
            "/auth/mfa/disable",
            json={"code": _next_code(secret)},
            cookies=updated_cookies,
        )
        assert r.status_code == 204

        r = await client.get("/auth/mfa/status", cookies=updated_cookies)
        assert r.json()["enabled"] is False

    async def test_mfa_regenerate_backup_codes_endpoint(self, client):
        _, cookies = await self._signup_and_login(client)
        secret, old_codes, updated_cookies = await self._enable_mfa_http(client, cookies)

        r = await client.post(
            "/auth/mfa/backup-codes/regenerate",
            json={"code": _next_code(secret)},
            cookies=updated_cookies,
        )
        assert r.status_code == 200
        new_codes = r.json()
        assert len(new_codes) == 10
        assert set(new_codes) != set(old_codes)
