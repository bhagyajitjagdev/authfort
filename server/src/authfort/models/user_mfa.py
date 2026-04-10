import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authfort.models.base import Base
from authfort.utils import TZDateTime, utc_now


class UserMFA(Base):
    __tablename__ = "authfort_user_mfa"
    __table_args__ = (UniqueConstraint("user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("authfort_users.id", ondelete="CASCADE"), index=True
    )
    totp_secret: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True, default=None)
    last_used_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True, default=None)
    last_used_code: Mapped[str | None] = mapped_column(String(6), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False, default=utc_now)
