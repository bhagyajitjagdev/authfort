"""Initial AuthFort schema — all 6 tables with authfort_ prefix.

Revision ID: 001
Create Date: 2026-02-19
"""

import sqlalchemy as sa
from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- authfort_users (no FKs — must be first) ---
    op.create_table(
        "authfort_users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("banned", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authfort_users_email", "authfort_users", ["email"], unique=True)

    # --- authfort_signing_keys (no FKs) ---
    op.create_table(
        "authfort_signing_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kid", sa.String(255), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(10), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_authfort_signing_keys_kid", "authfort_signing_keys", ["kid"], unique=True)

    # --- authfort_accounts (FK → authfort_users) ---
    op.create_table(
        "authfort_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("authfort_users.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("provider_account_id", sa.String(255), nullable=True),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "provider_account_id"),
    )
    op.create_index("ix_authfort_accounts_user_id", "authfort_accounts", ["user_id"])

    # --- authfort_refresh_tokens (FK → authfort_users, self-ref FK) ---
    op.create_table(
        "authfort_refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("authfort_users.id"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("replaced_by", sa.Uuid(), sa.ForeignKey("authfort_refresh_tokens.id"), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
    )
    op.create_index("ix_authfort_refresh_tokens_user_id", "authfort_refresh_tokens", ["user_id"])
    op.create_index("ix_authfort_refresh_tokens_token_hash", "authfort_refresh_tokens", ["token_hash"], unique=True)

    # --- authfort_user_roles (FK → authfort_users) ---
    op.create_table(
        "authfort_user_roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("authfort_users.id"), nullable=False),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "role"),
    )
    op.create_index("ix_authfort_user_roles_user_id", "authfort_user_roles", ["user_id"])

    # --- authfort_verification_tokens (FK → authfort_users) ---
    op.create_table(
        "authfort_verification_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("authfort_users.id"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authfort_verification_tokens_user_id", "authfort_verification_tokens", ["user_id"])
    op.create_index("ix_authfort_verification_tokens_token_hash", "authfort_verification_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    # Drop in reverse FK order
    op.drop_table("authfort_verification_tokens")
    op.drop_table("authfort_user_roles")
    op.drop_table("authfort_refresh_tokens")
    op.drop_table("authfort_accounts")
    op.drop_table("authfort_signing_keys")
    op.drop_table("authfort_users")
