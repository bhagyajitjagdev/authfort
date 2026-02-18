"""FastAPI integration for AuthFort."""

from authfort.integrations.fastapi.deps import create_current_user_dep, create_require_role_dep
from authfort.integrations.fastapi.oauth_router import create_oauth_router
from authfort.integrations.fastapi.router import create_auth_router

__all__ = [
    "create_auth_router",
    "create_current_user_dep",
    "create_require_role_dep",
    "create_oauth_router",
]
