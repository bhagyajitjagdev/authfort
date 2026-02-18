from datetime import UTC, datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    return datetime.now(UTC)


class TZDateTime(TypeDecorator):
    """DateTime that ensures timezone-aware values across all backends.

    PostgreSQL returns timezone-aware datetimes natively.
    SQLite returns naive datetimes — this adds UTC on read.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value