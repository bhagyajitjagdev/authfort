"""Tests for RedisRateLimitStore — fake async Redis client, no server needed.

The fake implements exactly the command subset the store uses (zset ops +
pipeline + scan), with real Redis semantics, so the store's orchestration and
sliding-window math are exercised without infrastructure. An optional
integration test at the bottom runs against a real Redis when REDIS_URL is set.
"""

import os
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from authfort import AuthFort, CookieConfig, RateLimitConfig, RedisRateLimitStore
from authfort.ratelimit import InMemoryStore, RateLimit, store_hit

pytestmark = pytest.mark.asyncio

from conftest import TEST_DATABASE_URL


def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Fake async Redis (zset subset)
# ---------------------------------------------------------------------------


class FakePipeline:
    def __init__(self, fake: "FakeAsyncRedis"):
        self._fake = fake
        self._queue = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def zremrangebyscore(self, key, lo, hi):
        self._queue.append(("zremrangebyscore", key, lo, hi))
        return self

    def zadd(self, key, mapping):
        self._queue.append(("zadd", key, mapping))
        return self

    def zcard(self, key):
        self._queue.append(("zcard", key))
        return self

    def expire(self, key, seconds):
        self._queue.append(("expire", key, seconds))
        return self

    async def execute(self):
        results = []
        for cmd, *args in self._queue:
            results.append(await getattr(self._fake, cmd)(*args))
        self._queue = []
        return results


class FakeAsyncRedis:
    """Minimal async Redis fake: sorted sets stored as {key: {member: score}}."""

    def __init__(self):
        self.zsets: dict[str, dict[str, float]] = {}

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    async def zremrangebyscore(self, key, lo, hi):
        zset = self.zsets.get(key, {})
        removed = [m for m, s in zset.items() if lo <= s <= hi]
        for m in removed:
            del zset[m]
        return len(removed)

    async def zadd(self, key, mapping):
        zset = self.zsets.setdefault(key, {})
        added = sum(1 for m in mapping if m not in zset)
        zset.update(mapping)
        return added

    async def zcard(self, key):
        return len(self.zsets.get(key, {}))

    async def expire(self, key, seconds):
        return key in self.zsets

    async def zrem(self, key, *members):
        zset = self.zsets.get(key, {})
        removed = sum(1 for m in members if zset.pop(m, None) is not None)
        return removed

    async def zrange(self, key, start, end, withscores=False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1])
        end = len(items) if end == -1 else end + 1
        sliced = items[start:end]
        if withscores:
            return [(m, s) for m, s in sliced]
        return [m for m, _ in sliced]

    async def delete(self, *keys):
        removed = sum(1 for k in keys if self.zsets.pop(k, None) is not None)
        return removed

    async def scan_iter(self, match=None):
        prefix = match.rstrip("*") if match else ""
        for key in list(self.zsets):
            if key.startswith(prefix):
                yield key


# ---------------------------------------------------------------------------
# Unit tests: RedisRateLimitStore against the fake
# ---------------------------------------------------------------------------


class TestRedisRateLimitStore:
    def make_store(self, now: float = 1000.0):
        fake = FakeAsyncRedis()
        clock = {"now": now}
        store = RedisRateLimitStore(fake, time_func=lambda: clock["now"])
        return store, fake, clock

    async def test_basic_hit_allowed(self):
        store, _, _ = self.make_store()
        allowed, remaining, retry_after = await store.hit("k", RateLimit(3, 60))
        assert allowed is True
        assert remaining == 2
        assert retry_after == 0.0

    async def test_hits_exhaust_limit(self):
        store, _, _ = self.make_store()
        limit = RateLimit(3, 60)
        for _ in range(3):
            allowed, *_ = await store.hit("k", limit)
            assert allowed is True
        allowed, remaining, retry_after = await store.hit("k", limit)
        assert allowed is False
        assert remaining == 0
        assert retry_after > 0

    async def test_rejected_hit_does_not_consume_slot(self):
        store, fake, _ = self.make_store()
        limit = RateLimit(2, 60)
        await store.hit("k", limit)
        await store.hit("k", limit)
        await store.hit("k", limit)  # rejected
        # Only the 2 accepted hits remain in the zset
        assert len(fake.zsets["authfort:rl:k"]) == 2

    async def test_window_expiry_allows_again(self):
        store, _, clock = self.make_store(now=1000.0)
        limit = RateLimit(2, 60)
        await store.hit("k", limit)
        await store.hit("k", limit)
        allowed, *_ = await store.hit("k", limit)
        assert allowed is False

        clock["now"] = 1061.0  # past the window
        allowed, remaining, _ = await store.hit("k", limit)
        assert allowed is True
        assert remaining == 1

    async def test_sliding_window(self):
        store, _, clock = self.make_store(now=1000.0)
        limit = RateLimit(2, 60)
        await store.hit("k", limit)          # t=1000
        clock["now"] = 1030.0
        await store.hit("k", limit)          # t=1030
        clock["now"] = 1045.0
        allowed, *_ = await store.hit("k", limit)
        assert allowed is False              # both still in window
        clock["now"] = 1061.0                # first hit expired, second remains
        allowed, remaining, _ = await store.hit("k", limit)
        assert allowed is True
        assert remaining == 0

    async def test_retry_after_matches_oldest_entry(self):
        store, _, clock = self.make_store(now=1000.0)
        limit = RateLimit(1, 60)
        await store.hit("k", limit)
        clock["now"] = 1010.0
        allowed, _, retry_after = await store.hit("k", limit)
        assert allowed is False
        assert retry_after == pytest.approx(50.0)

    async def test_different_keys_independent(self):
        store, _, _ = self.make_store()
        limit = RateLimit(1, 60)
        allowed_a, *_ = await store.hit("a", limit)
        allowed_b, *_ = await store.hit("b", limit)
        assert allowed_a is True
        assert allowed_b is True

    async def test_key_prefix_applied(self):
        fake = FakeAsyncRedis()
        store = RedisRateLimitStore(fake, key_prefix="myapp:", time_func=lambda: 1000.0)
        await store.hit("ip:1.2.3.4:login", RateLimit(5, 60))
        assert list(fake.zsets) == ["myapp:ip:1.2.3.4:login"]

    async def test_concurrent_same_tick_hits_counted_separately(self):
        # Same clock value for every hit — unique members must prevent collapse
        store, fake, _ = self.make_store()
        limit = RateLimit(5, 60)
        for _ in range(3):
            await store.hit("k", limit)
        assert len(fake.zsets["authfort:rl:k"]) == 3

    async def test_reset_specific_key(self):
        store, fake, _ = self.make_store()
        limit = RateLimit(1, 60)
        await store.hit("a", limit)
        await store.hit("b", limit)
        await store.reset("a")
        allowed, *_ = await store.hit("a", limit)
        assert allowed is True
        allowed, *_ = await store.hit("b", limit)
        assert allowed is False

    async def test_reset_all(self):
        store, fake, _ = self.make_store()
        limit = RateLimit(1, 60)
        await store.hit("a", limit)
        await store.hit("b", limit)
        await store.reset()
        assert fake.zsets == {}


# ---------------------------------------------------------------------------
# store_hit helper — sync and async stores through one call path
# ---------------------------------------------------------------------------


class TestStoreHit:
    async def test_sync_store(self):
        store = InMemoryStore(time_func=lambda: 1000.0)
        allowed, remaining, retry_after = await store_hit(store, "k", RateLimit(2, 60))
        assert (allowed, remaining, retry_after) == (True, 1, 0.0)

    async def test_async_store(self):
        store = RedisRateLimitStore(FakeAsyncRedis(), time_func=lambda: 1000.0)
        allowed, remaining, retry_after = await store_hit(store, "k", RateLimit(2, 60))
        assert (allowed, remaining, retry_after) == (True, 1, 0.0)


# ---------------------------------------------------------------------------
# HTTP integration — async store wired through AuthFort + FastAPI
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_redis_rl():
    instance = AuthFort(
        database_url=TEST_DATABASE_URL,
        cookie=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(login="2/min"),
        rate_limit_store=RedisRateLimitStore(FakeAsyncRedis()),
    )
    await instance.migrate()
    yield instance
    await instance.dispose()


@pytest_asyncio.fixture
async def redis_rl_client(auth_redis_rl: AuthFort):
    app = FastAPI()
    app.include_router(auth_redis_rl.fastapi_router(), prefix="/auth")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        yield client


class TestRedisStoreIntegration:
    async def test_custom_store_used(self, auth_redis_rl):
        assert isinstance(auth_redis_rl.rate_limit_store, RedisRateLimitStore)

    async def test_login_rate_limited_via_async_store(self, auth_redis_rl, redis_rl_client):
        email = unique_email()
        await auth_redis_rl.create_user(email, "testpassword123")
        await auth_redis_rl.rate_limit_store.reset()

        for _ in range(2):
            resp = await redis_rl_client.post("/auth/login", json={
                "email": email, "password": "wrongpassword",
            })
            assert resp.status_code != 429

        resp = await redis_rl_client.post("/auth/login", json={
            "email": email, "password": "wrongpassword",
        })
        assert resp.status_code == 429
        assert resp.json()["detail"]["error"] == "rate_limit_exceeded"
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# Optional: real Redis integration (set REDIS_URL to enable)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("REDIS_URL"), reason="REDIS_URL not set")
class TestRealRedis:
    async def test_hit_and_reset_against_real_redis(self):
        store = RedisRateLimitStore.from_url(
            os.environ["REDIS_URL"], key_prefix=f"authfort:test:{uuid.uuid4().hex}:",
        )
        limit = RateLimit(2, 60)
        key = "ip:127.0.0.1:login"
        assert (await store.hit(key, limit))[0] is True
        assert (await store.hit(key, limit))[0] is True
        allowed, _, retry_after = await store.hit(key, limit)
        assert allowed is False
        assert retry_after > 0
        await store.reset()
        assert (await store.hit(key, limit))[0] is True
