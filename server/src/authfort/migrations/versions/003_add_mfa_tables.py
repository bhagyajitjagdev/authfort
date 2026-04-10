"""Add TOTP MFA tables — authfort_user_mfa and authfort_mfa_backup_codes.

Revision ID: 003
Revises: 002
Create Date: 2026-04-10
"""

import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- authfort_user_mfa (one row per user who has set up MFA) ---
    op.create_table(
        "authfort_user_mfa",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id", sa.Uuid(),
            sa.ForeignKey("authfort_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("totp_secret", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_code", sa.String(6), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authfort_user_mfa_user_id", "authfort_user_mfa", ["user_id"], unique=True)

    # --- authfort_mfa_backup_codes (backup codes for account recovery) ---
    op.create_table(
        "authfort_mfa_backup_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id", sa.Uuid(),
            sa.ForeignKey("authfort_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_authfort_mfa_backup_codes_user_id",
        "authfort_mfa_backup_codes",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_authfort_mfa_backup_codes_user_id", table_name="authfort_mfa_backup_codes")
    op.drop_table("authfort_mfa_backup_codes")
    op.drop_index("ix_authfort_user_mfa_user_id", table_name="authfort_user_mfa")
    op.drop_table("authfort_user_mfa")
