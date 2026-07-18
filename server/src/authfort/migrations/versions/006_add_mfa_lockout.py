"""Add failed_attempts + locked_until to authfort_user_mfa for brute-force lockout.

DB-backed counter so the lockout holds across processes/replicas: after N
consecutive failed MFA verification attempts (config mfa_max_failed_attempts),
MFA login is locked for mfa_lockout_seconds. Independent of the opt-in,
IP-keyed rate limiter.

Revision ID: 006
Revises: 005
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "authfort_user_mfa",
        sa.Column(
            "failed_attempts", sa.Integer(), nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "authfort_user_mfa",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("authfort_user_mfa", "locked_until")
    op.drop_column("authfort_user_mfa", "failed_attempts")
