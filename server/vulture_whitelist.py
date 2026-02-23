"""Vulture whitelist — false positives that are actually used by frameworks."""

# ---------------------------------------------------------------------------
# Public API methods on AuthFort (used by consumers, not internally)
# ---------------------------------------------------------------------------
from authfort.authfort import AuthFort

AuthFort.on
AuthFort.add_hook
AuthFort.get_provider_tokens
AuthFort.rotate_key
AuthFort.cleanup_expired_keys
AuthFort.cleanup_expired_tokens
AuthFort.cleanup_expired_sessions
AuthFort.get_jwks
AuthFort.fastapi_router
AuthFort.jwks_router
AuthFort.require_role
AuthFort.migrate

# ---------------------------------------------------------------------------
# FastAPI route handlers (registered via decorators, not called directly)
# ---------------------------------------------------------------------------
_.signup_endpoint
_.login_endpoint
_.refresh_endpoint
_.logout_endpoint
_.me_endpoint
_.oauth_authorize
_.oauth_callback
_.introspect_endpoint
_.jwks_endpoint

# ---------------------------------------------------------------------------
# Pydantic / dataclass fields (used for serialization, not accessed in code)
# ---------------------------------------------------------------------------
_.expires_in
_.timestamp
_.revoke_all
_.new_kid
_.fields
_.active
_.sub
_.exp
_.iat
_.iss
_.updated_at

# ---------------------------------------------------------------------------
# Alembic migration variables (required by Alembic framework)
# ---------------------------------------------------------------------------
_.revision
_.down_revision
_.branch_labels
_.depends_on
_.downgrade

# ---------------------------------------------------------------------------
# Alembic include_object callback params (required by signature)
# ---------------------------------------------------------------------------
_.compare_to
_.reflected

# ---------------------------------------------------------------------------
# SQLAlchemy TypeDecorator (required by SQLAlchemy framework)
# ---------------------------------------------------------------------------
from authfort.utils import TZDateTime

TZDateTime.impl
TZDateTime.cache_ok
TZDateTime.process_result_value
_.dialect  # required param in TypeDecorator.process_result_value

# ---------------------------------------------------------------------------
# Repository utility (used in tests, useful for admin/debugging)
# ---------------------------------------------------------------------------
_.get_all_signing_keys
