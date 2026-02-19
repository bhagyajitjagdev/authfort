"""Programmatic Alembic environment for AuthFort bundled migrations.

This env.py is never called directly — it's invoked by Alembic's runtime
when auth.migrate() calls alembic.command.upgrade().

The sync connection is passed via config.attributes["connection"].
"""

from alembic import context

config = context.config


def run_migrations_online() -> None:
    """Run migrations using a pre-provided connection."""
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError(
            "No connection provided. Use auth.migrate() to run migrations."
        )

    context.configure(
        connection=connection,
        target_metadata=None,
        version_table="authfort_alembic_version",
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
