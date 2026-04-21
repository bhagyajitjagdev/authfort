"""AuthFort SQLAlchemy models — central registry.

Import all models here so Base.metadata is populated for Alembic.
"""

from authfort.models.base import Base
from authfort.models.account import Account
from authfort.models.password_history import PasswordHistory
from authfort.models.refresh_token import RefreshToken
from authfort.models.signing_key import SigningKey
from authfort.models.user import User
from authfort.models.user_role import UserRole
from authfort.models.verification_token import VerificationToken

__all__ = [
    "Base",
    "User",
    "Account",
    "PasswordHistory",
    "RefreshToken",
    "UserRole",
    "SigningKey",
    "VerificationToken",
]
