"""Vulture whitelist — false positives that are actually used by frameworks."""

# ---------------------------------------------------------------------------
# Public API methods on ServiceAuth (used by consumers, not internally)
# ---------------------------------------------------------------------------
from authfort_service.service_auth import ServiceAuth

ServiceAuth.verify_token
ServiceAuth.require_role

from authfort_service.jwks import JWKSFetcher

JWKSFetcher.get_key

# ---------------------------------------------------------------------------
# Dataclass / response fields (used for serialization)
# ---------------------------------------------------------------------------
_.active
_.sub
_.email
_.name
_.token_version
_.exp
_.iat
_.iss
