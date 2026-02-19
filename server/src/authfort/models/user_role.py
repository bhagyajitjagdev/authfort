import uuid
from datetime import datetime

from sqlmodel import Column, Field, SQLModel, UniqueConstraint

from authfort.utils import TZDateTime, utc_now


class UserRole(SQLModel, table=True):
    __tablename__ = "authfort_user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="authfort_users.id", index=True)
    role: str = Field(max_length=50)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(TZDateTime(), nullable=False),
    )
