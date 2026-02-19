"""Add composite index on refresh_tokens(user_id, revoked) for query performance.

Revision ID: 002
Create Date: 2026-02-19
"""

from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_authfort_refresh_tokens_user_id_revoked",
        "authfort_refresh_tokens",
        ["user_id", "revoked"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_authfort_refresh_tokens_user_id_revoked",
        table_name="authfort_refresh_tokens",
    )
