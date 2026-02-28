"""Reverse proxy IP extraction for FastAPI requests."""

from ipaddress import ip_address

from fastapi import Request

from authfort.config import AuthFortConfig


def get_client_ip(request: Request, config: AuthFortConfig) -> str | None:
    """Extract the real client IP, respecting proxy configuration.

    Resolution order:
    1. If neither trust_proxy nor trusted_proxy_networks is set → request.client.host.
    2. If trusted_proxy_networks is set → only read headers when the direct IP
       is in a trusted network (spoofing prevention).
    3. If trust_proxy is True (no networks) → always read headers.
    4. Header priority: X-Forwarded-For (first value) > X-Real-IP > direct IP.
    """
    if request.client is None:
        return None

    direct_ip = request.client.host

    if not config.trust_proxy and not config.trusted_proxy_networks:
        return direct_ip

    # Strict mode: only trust headers from known proxy IPs/CIDRs
    if config.trusted_proxy_networks:
        try:
            addr = ip_address(direct_ip)
        except ValueError:
            return direct_ip
        if not any(addr in net for net in config.trusted_proxy_networks):
            return direct_ip

    # Read proxy headers
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    return direct_ip
