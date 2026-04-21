import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authfort.models.base import Base
from authfort.utils import TZDateTime, utc_now


class PasswordHistory(Base):
    __tablename__ = "authfort_password_history"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("authfort_users.id", ondelete="CASCADE"), index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), nullable=False, default=utc_now)
