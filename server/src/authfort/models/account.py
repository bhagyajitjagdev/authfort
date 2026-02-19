import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authfort.models.base import Base
from authfort.utils import TZDateTime, utc_now


class Account(Base):
    __tablename__ = "authfort_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_account_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("authfort_users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_account_id: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False, default=utc_now)
