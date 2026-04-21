"""Add authfort_password_history table for password reuse prevention.

Revision ID: 004
Revises: 003
Create Date: 2026-04-21
"""

import sqlalchemy as sa
from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authfort_password_history",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id", sa.Uuid(),
            sa.ForeignKey("authfort_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_authfort_password_history_user_id",
        "authfort_password_history",
        ["user_id"],
    )
    op.create_index(
        "ix_authfort_password_history_user_created",
        "authfort_password_history",
        ["user_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_authfort_password_history_user_created",
        table_name="authfort_password_history",
    )
    op.drop_index(
        "ix_authfort_password_history_user_id",
        table_name="authfort_password_history",
    )
    op.drop_table("authfort_password_history")
