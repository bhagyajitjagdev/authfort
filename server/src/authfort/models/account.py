import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel, UniqueConstraint

from authfort.utils import TZDateTime, utc_now


class Account(SQLModel, table=True):
    __tablename__ = "authfort_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_account_id"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="authfort_users.id", index=True)
    provider: str = Field(max_length=50)
    provider_account_id: str | None = Field(default=None, max_length=255)
    access_token: str | None = Field(default=None)
    refresh_token: str | None = Field(default=None)
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(TZDateTime(), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
