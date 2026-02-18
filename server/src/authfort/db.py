"""Database engine and session management — no global state."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool, StaticPool
from sqlmodel.ext.asyncio.session import AsyncSession


def create_engine(database_url: str) -> AsyncEngine:
    """Create async engine with dialect-appropriate settings.

    Supports PostgreSQL (asyncpg), SQLite (aiosqlite), and MySQL (aiomysql).
    """
    if database_url.startswith("sqlite"):
        kwargs = dict(
            poolclass=StaticPool if ":memory:" in database_url else NullPool,
            connect_args={"check_same_thread": False},
        )
    else:
        kwargs = dict(
            poolclass=AsyncAdaptedQueuePool,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

    return create_async_engine(database_url, echo=False, **kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


@asynccontextmanager
async def get_session(session_factory: async_sessionmaker[AsyncSession]) -> AsyncGenerator[AsyncSession]:
    """Get an async database session (context manager for service/controller logic)."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
