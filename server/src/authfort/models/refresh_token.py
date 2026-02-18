import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel

from authfort.utils import TZDateTime, utc_now


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="users.id", index=True)
    token_hash: str = Field(max_length=255, unique=True)
    expires_at: datetime = Field(
        sa_column=Column(TZDateTime(), nullable=False),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
    revoked: bool = Field(default=False)
    replaced_by: uuid.UUID | None = Field(default=None, foreign_key="refresh_tokens.id")
    user_agent: str | None = Field(default=None)
    ip_address: str | None = Field(default=None, max_length=45)
