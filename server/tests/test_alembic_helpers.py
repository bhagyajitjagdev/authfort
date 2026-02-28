"""Tests for Alembic helper functions and CLI."""

import subprocess
import sys
import uuid

import sqlalchemy as sa
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from authfort.alembic_helper import (
    AUTHFORT_TABLES,
    alembic_filters,
    register_foreign_tables,
)


# ---------------------------------------------------------------------------
# register_foreign_tables
# ---------------------------------------------------------------------------


class TestRegisterForeignTables:
    def test_registers_users_table(self):
        metadata = sa.MetaData()
        register_foreign_tables(metadata)
        assert "authfort_users" in metadata.tables

    def test_registers_user_roles_table(self):
        metadata = sa.MetaData()
        register_foreign_tables(metadata)
        assert "authfort_user_roles" in metadata.tables

    def test_users_table_has_id_pk(self):
        metadata = sa.MetaData()
        register_foreign_tables(metadata)
        users_table = metadata.tables["authfort_users"]
        pk_cols = [c.name for c in users_table.primary_key.columns]
        assert pk_cols == ["id"]

    def test_user_roles_table_has_id_pk(self):
        metadata = sa.MetaData()
        register_foreign_tables(metadata)
        roles_table = metadata.tables["authfort_user_roles"]
        pk_cols = [c.name for c in roles_table.primary_key.columns]
        assert pk_cols == ["id"]

    def test_idempotent_call(self):
        metadata = sa.MetaData()
        register_foreign_tables(metadata)
        register_foreign_tables(metadata)
        assert "authfort_users" in metadata.tables
        assert "authfort_user_roles" in metadata.tables

    def test_does_not_overwrite_existing_table(self):
        metadata = sa.MetaData()
        # Pre-register a table with extra columns
        sa.Table(
            "authfort_users",
            metadata,
            sa.Column("id", sa.Uuid, primary_key=True),
            sa.Column("email", sa.String(255)),
        )
        register_foreign_tables(metadata)
        users_table = metadata.tables["authfort_users"]
        col_names = [c.name for c in users_table.columns]
        assert "email" in col_names

    def test_fk_resolution_with_declarative_base(self):
        """Consumer models can FK to authfort_users.id after registration."""

        class Base(DeclarativeBase):
            pass

        register_foreign_tables(Base.metadata)

        class Order(Base):
            __tablename__ = "orders"
            id: Mapped[uuid.UUID] = mapped_column(
                sa.Uuid, primary_key=True, default=uuid.uuid4
            )
            user_id: Mapped[uuid.UUID] = mapped_column(
                sa.Uuid, ForeignKey("authfort_users.id")
            )

        # If FK resolution failed, the class definition above would raise
        assert "user_id" in Order.__table__.columns


# ---------------------------------------------------------------------------
# alembic_filters
# ---------------------------------------------------------------------------


class TestAlembicFilters:
    def test_returns_dict_with_both_keys(self):
        filters = alembic_filters()
        assert "include_name" in filters
        assert "include_object" in filters

    def test_include_name_rejects_authfort_tables(self):
        filters = alembic_filters()
        include_name = filters["include_name"]
        for table in AUTHFORT_TABLES:
            assert include_name(table, "table", {}) is False

    def test_include_name_accepts_other_tables(self):
        filters = alembic_filters()
        include_name = filters["include_name"]
        assert include_name("orders", "table", {}) is True
        assert include_name("my_users", "table", {}) is True

    def test_include_name_accepts_non_table_types(self):
        filters = alembic_filters()
        include_name = filters["include_name"]
        assert include_name("authfort_users", "index", {}) is True

    def test_include_name_handles_none_name(self):
        filters = alembic_filters()
        include_name = filters["include_name"]
        assert include_name(None, "table", {}) is True

    def test_include_object_rejects_authfort_tables(self):
        filters = alembic_filters()
        include_object = filters["include_object"]
        for table in AUTHFORT_TABLES:
            assert include_object(None, table, "table", True, None) is False

    def test_include_object_accepts_other_tables(self):
        filters = alembic_filters()
        include_object = filters["include_object"]
        assert include_object(None, "orders", "table", True, None) is True

    def test_include_object_accepts_non_table_types(self):
        filters = alembic_filters()
        include_object = filters["include_object"]
        assert (
            include_object(None, "authfort_users", "index", True, None) is True
        )

    def test_include_object_handles_none_name(self):
        filters = alembic_filters()
        include_object = filters["include_object"]
        assert include_object(None, None, "table", True, None) is True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "authfort.cli", "migrate", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--database-url" in result.stdout

    def test_no_command_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "authfort.cli"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_migrate_missing_url_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "authfort.cli", "migrate"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
