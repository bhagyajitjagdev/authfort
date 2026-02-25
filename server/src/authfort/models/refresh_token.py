import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authfort.models.base import Base
from authfort.utils import TZDateTime, utc_now


class RefreshToken(Base):
    __tablename__ = "authfort_refresh_tokens"
    __table_args__ = (
        Index("ix_authfort_refresh_tokens_user_id_revoked", "user_id", "revoked"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("authfort_users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False, default=utc_now)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("authfort_refresh_tokens.id", ondelete="SET NULL"), nullable=True, default=None)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, default=None)
