import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel

from authfort.utils import TZDateTime, utc_now


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(max_length=255, unique=True, index=True)
    email_verified: bool = Field(default=False)
    name: str | None = Field(default=None, max_length=255)
    avatar_url: str | None = Field(default=None)
    password_hash: str | None = Field(default=None, max_length=255)
    token_version: int = Field(default=0)
    banned: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
