"""Alembic helpers for developers sharing a database with AuthFort."""

import uuid
from typing import Any

import sqlalchemy as sa

AUTHFORT_TABLES = frozenset(
    {
        "authfort_users",
        "authfort_accounts",
        "authfort_refresh_tokens",
        "authfort_user_roles",
        "authfort_signing_keys",
        "authfort_verification_tokens",
        "authfort_alembic_version",
    }
)


def register_foreign_tables(metadata: sa.MetaData) -> None:
    """Register AuthFort table stubs in your MetaData for FK resolution.

    Call this once, **before** your models that FK to AuthFort tables are
    defined::

        from sqlalchemy.orm import DeclarativeBase
        from authfort import register_foreign_tables

        class Base(DeclarativeBase):
            pass

        register_foreign_tables(Base.metadata)

        # Now your models can use ForeignKey("authfort_users.id")
    """
    if "authfort_users" not in metadata.tables:
        sa.Table(
            "authfort_users",
            metadata,
            sa.Column("id", sa.Uuid, primary_key=True, default=uuid.uuid4),
            extend_existing=True,
        )
    if "authfort_user_roles" not in metadata.tables:
        sa.Table(
            "authfort_user_roles",
            metadata,
            sa.Column("id", sa.Uuid, primary_key=True, default=uuid.uuid4),
            extend_existing=True,
        )


def alembic_filters() -> dict[str, Any]:
    """Return Alembic filters that skip all AuthFort-managed tables.

    Returns a dict with ``include_name`` and ``include_object`` callables.
    Spread into your ``context.configure()``::

        from authfort import alembic_filters

        context.configure(
            ...,
            **alembic_filters(),
        )
    """

    def include_name(name: str | None, type_: str, parent_names: dict) -> bool:
        if type_ == "table" and name is not None and name in AUTHFORT_TABLES:
            return False
        return True

    def include_object(
        object: Any, name: str | None, type_: str, reflected: bool, compare_to: Any
    ) -> bool:
        if type_ == "table" and name is not None and name in AUTHFORT_TABLES:
            return False
        return True

    return {"include_name": include_name, "include_object": include_object}
