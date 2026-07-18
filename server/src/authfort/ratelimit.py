"""Rate limiting — sliding window counter with pluggable storage."""

import inspect
import math
import secrets
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class RateLimit:
    """Parsed rate limit: max_requests within window_seconds."""

    max_requests: int
    window_seconds: int


_PERIOD_MAP = {
    "sec": 1,
    "second": 1,
    "seconds": 1,
    "min": 60,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
}


def parse_rate_limit(value: str) -> RateLimit:
    """Parse a rate limit string like '5/min' into a RateLimit.

    Supported formats: '{count}/{period}'
    Periods: sec, second, min, minute, hour, day (and plurals).

    Raises ValueError on invalid format.
    """
    parts = value.strip().split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid rate limit format: '{value}'. Expected 'count/period'.")

    count_str, period_str = parts
    try:
        count = int(count_str.strip())
    except ValueError:
        raise ValueError(f"Invalid rate limit count: '{count_str.strip()}'")

    if count <= 0:
        raise ValueError(f"Rate limit count must be positive, got {count}")

    period_str = period_str.strip().lower()
    if period_str not in _PERIOD_MAP:
        raise ValueError(
            f"Unknown rate limit period: '{period_str}'. "
            f"Valid periods: {', '.join(sorted(_PERIOD_MAP))}"
        )

    return RateLimit(max_requests=count, window_seconds=_PERIOD_MAP[period_str])


@runtime_checkable
class RateLimitStore(Protocol):
    """Protocol for rate limit storage backends.

    Implementations must be thread-safe for use with sync workers.
    Both methods may be either sync or async — async implementations
    (e.g. RedisRateLimitStore) return awaitables, which the integration
    layer awaits via store_hit().
    """

    def hit(self, key: str, limit: RateLimit) -> tuple[bool, int, float]:
        """Record a hit and check if the limit is exceeded.

        Args:
            key: The rate limit key (e.g. "ip:1.2.3.4:login").
            limit: The rate limit to check against.

        Returns:
            Tuple of (allowed, remaining, retry_after_seconds).
            - allowed: True if the request should proceed.
            - remaining: Number of requests left in the window.
            - retry_after: Seconds until the oldest entry expires (0 if allowed).
        """
        ...

    def reset(self, key: str | None = None) -> None:
        """Reset rate limit state. If key is None, reset all keys."""
        ...


async def store_hit(store, key: str, limit: RateLimit) -> tuple[bool, int, float]:
    """Call store.hit(), awaiting the result if the store is async."""
    result = store.hit(key, limit)
    if inspect.isawaitable(result):
        result = await result
    return result


class InMemoryStore:
    """Thread-safe in-memory sliding window counter.

    Each key maps to a sorted list of timestamps. On each hit, expired
    entries are pruned, the new timestamp is appended, and the count
    is checked against the limit.

    Suitable for single-process deployments. Multi-process deployments
    (e.g. gunicorn with multiple workers) do not share state — effective
    rate limits are multiplied by the number of workers. Use a Redis-backed
    store for strict multi-process rate limiting.
    """

    def __init__(self, time_func: Callable[[], float] | None = None) -> None:
        self._time_func = time_func or time.monotonic
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: RateLimit) -> tuple[bool, int, float]:
        now = self._time_func()
        window_start = now - limit.window_seconds

        with self._lock:
            timestamps = self._buckets[key]

            # Prune expired entries
            prune_idx = 0
            for i, ts in enumerate(timestamps):
                if ts > window_start:
                    prune_idx = i
                    break
            else:
                # All entries are expired (or list is empty)
                prune_idx = len(timestamps)

            if prune_idx > 0:
                del timestamps[:prune_idx]

            current_count = len(timestamps)

            if current_count >= limit.max_requests:
                # Rate limited — calculate retry_after from oldest entry
                retry_after = timestamps[0] + limit.window_seconds - now
                return (False, 0, max(retry_after, 0.1))

            # Allowed — record this hit
            timestamps.append(now)
            remaining = limit.max_requests - len(timestamps)
            return (True, remaining, 0.0)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


class RedisRateLimitStore:
    """Redis-backed sliding window counter — shared across processes/replicas.

    Uses one sorted set per key: each hit is a ZSET member scored by its
    timestamp. On each hit (in a MULTI/EXEC pipeline): expired members are
    pruned, the new hit is added, and the count is checked against the limit.
    Semantics match InMemoryStore.

    Use this instead of the default InMemoryStore whenever the app runs with
    more than one process (gunicorn/uvicorn workers, multiple replicas) —
    per-process in-memory buckets multiply the effective limits by the
    worker count.

    Usage::

        import redis.asyncio as redis
        from authfort import AuthFort, RateLimitConfig, RedisRateLimitStore

        auth = AuthFort(
            database_url=...,
            rate_limit=RateLimitConfig(),
            rate_limit_store=RedisRateLimitStore(redis.from_url("redis://localhost:6379")),
        )

    Or without constructing a client yourself::

        rate_limit_store=RedisRateLimitStore.from_url("redis://localhost:6379")

    Notes:
        - The client must be an async Redis client (``redis.asyncio.Redis``).
        - Timestamps use the app server's wall clock; keep clocks NTP-synced
          across replicas.
        - Fails closed: if Redis is unreachable, hit() raises and the request
          errors — rate limiting is a security control, silently allowing
          traffic on backend failure would defeat it.
    """

    def __init__(
        self,
        client: Any,
        *,
        key_prefix: str = "authfort:rl:",
        time_func: Callable[[], float] | None = None,
    ) -> None:
        """
        Args:
            client: An async Redis client (``redis.asyncio.Redis`` or
                compatible duck-typed object).
            key_prefix: Namespace prefix for all rate limit keys.
            time_func: Clock override for testing (defaults to time.time —
                wall clock, since timestamps are shared across processes).
        """
        self._redis = client
        self._prefix = key_prefix
        self._time_func = time_func or time.time

    @classmethod
    def from_url(cls, url: str, *, key_prefix: str = "authfort:rl:") -> "RedisRateLimitStore":
        """Create a store from a Redis URL. Requires the ``redis`` package
        (install with ``authfort[redis]``)."""
        try:
            import redis.asyncio as _redis
        except ImportError as e:
            raise ImportError(
                "RedisRateLimitStore.from_url requires the 'redis' package. "
                "Install it with: uv add 'authfort[redis]'  (or: pip install redis)"
            ) from e
        return cls(_redis.from_url(url), key_prefix=key_prefix)

    async def hit(self, key: str, limit: RateLimit) -> tuple[bool, int, float]:
        now = self._time_func()
        window_start = now - limit.window_seconds
        rkey = self._prefix + key
        # Unique member per hit — concurrent hits in the same clock tick must
        # not collapse into one ZSET entry.
        member = f"{now:.6f}:{secrets.token_hex(4)}"

        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(rkey, 0, window_start)
            pipe.zadd(rkey, {member: now})
            pipe.zcard(rkey)
            pipe.expire(rkey, math.ceil(limit.window_seconds) + 1)
            _, _, count, _ = await pipe.execute()

        if count > limit.max_requests:
            # Over limit — this hit doesn't consume a slot; remove it and
            # report when the oldest counted hit leaves the window.
            await self._redis.zrem(rkey, member)
            oldest = await self._redis.zrange(rkey, 0, 0, withscores=True)
            if oldest:
                retry_after = oldest[0][1] + limit.window_seconds - now
            else:
                retry_after = limit.window_seconds
            return (False, 0, max(retry_after, 0.1))

        return (True, limit.max_requests - count, 0.0)

    async def reset(self, key: str | None = None) -> None:
        if key is not None:
            await self._redis.delete(self._prefix + key)
            return
        async for rkey in self._redis.scan_iter(match=self._prefix + "*"):
            await self._redis.delete(rkey)
