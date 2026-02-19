import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel

from authfort.utils import TZDateTime, utc_now


class VerificationToken(SQLModel, table=True):
    __tablename__ = "authfort_verification_tokens"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="authfort_users.id", index=True)
    token_hash: str = Field(max_length=255, unique=True)
    type: str = Field(max_length=20)
    expires_at: datetime = Field(
        sa_column=Column(TZDateTime(), nullable=False),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
