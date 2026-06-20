"""Add is_deleted + deleted_at to authfort_users for anonymize / soft-delete.

Supports the "erase the person, not the row" account-deletion pattern: the user
row and its id are retained (so external FKs stay valid) while PII and access are
stripped and the account is flagged deleted.

Revision ID: 005
Revises: 004
Create Date: 2026-06-20
"""

import sqlalchemy as sa
from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "authfort_users",
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "authfort_users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("authfort_users", "deleted_at")
    op.drop_column("authfort_users", "is_deleted")
