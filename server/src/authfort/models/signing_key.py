import uuid
from datetime import datetime

from sqlalchemy import Boolean, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authfort.models.base import Base
from authfort.utils import TZDateTime, utc_now


class SigningKey(Base):
    __tablename__ = "authfort_signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kid: Mapped[str] = mapped_column(String(255), unique=True)
    private_key: Mapped[str] = mapped_column(Text)
    public_key: Mapped[str] = mapped_column(Text)
    algorithm: Mapped[str] = mapped_column(String(10))
    is_current: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False, default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True, default=None)
