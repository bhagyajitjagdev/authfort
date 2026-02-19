import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel

from authfort.utils import TZDateTime, utc_now


class SigningKey(SQLModel, table=True):
    __tablename__ = "authfort_signing_keys"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    kid: str = Field(max_length=255, unique=True)
    private_key: str
    public_key: str
    algorithm: str = Field(max_length=10)
    is_current: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(TZDateTime(), nullable=True),
    )
