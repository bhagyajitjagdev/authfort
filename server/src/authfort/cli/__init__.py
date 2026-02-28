"""AuthFort CLI — database management commands."""

import argparse
import asyncio
import sys
from pathlib import Path


def main() -> None:
    """Entry point for the ``authfort`` console script."""
    parser = argparse.ArgumentParser(prog="authfort", description="AuthFort CLI")
    sub = parser.add_subparsers(dest="command")

    migrate_cmd = sub.add_parser("migrate", help="Run AuthFort database migrations")
    migrate_cmd.add_argument(
        "--database-url",
        required=True,
        help='Database URL (e.g. "postgresql+asyncpg://user:pass@host/db")',
    )

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "migrate":
        asyncio.run(_migrate(args.database_url))


async def _migrate(database_url: str) -> None:
    """Create an async engine and run bundled Alembic migrations."""
    from alembic.config import Config
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(database_url)
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parent.parent / "migrations"),
    )

    try:
        async with engine.begin() as conn:
            await conn.run_sync(_run_upgrade, config)
        print("AuthFort migrations applied successfully.")
    finally:
        await engine.dispose()


def _run_upgrade(connection, config) -> None:
    from alembic import command

    config.attributes["connection"] = connection
    command.upgrade(config, "head")
