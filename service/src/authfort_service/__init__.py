"""AuthFort Service — Lightweight JWT verification for microservices."""

__version__ = "0.0.16"

from authfort_service.introspect import IntrospectionResult
from authfort_service.service_auth import ServiceAuth
from authfort_service.verifier import TokenPayload, TokenVerificationError

__all__ = ["IntrospectionResult", "ServiceAuth", "TokenPayload", "TokenVerificationError"]
