"""Rate limiting — sliding window counter with pluggable storage."""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable


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
