"""Add session_id column to refresh tokens for stable session identity.

Revision ID: 002
Revises: 001
Create Date: 2026-02-28
"""

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "authfort_refresh_tokens",
        sa.Column("session_id", sa.Uuid(), nullable=True),
    )
    op.create_index(
        "ix_authfort_refresh_tokens_session_id",
        "authfort_refresh_tokens",
        ["session_id"],
    )
    # Backfill: existing tokens become their own session root
    op.execute("UPDATE authfort_refresh_tokens SET session_id = id WHERE session_id IS NULL")


def downgrade() -> None:
    op.drop_index("ix_authfort_refresh_tokens_session_id", table_name="authfort_refresh_tokens")
    op.drop_column("authfort_refresh_tokens", "session_id")
