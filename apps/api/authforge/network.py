import ipaddress

from fastapi import Request

from .config import Settings


def client_ip(request: Request, settings: Settings) -> str | None:
    if request.client is None:
        return None
    peer = request.client.host
    try:
        trusted = any(
            ipaddress.ip_address(peer) in ipaddress.ip_network(cidr)
            for cidr in settings.trusted_proxy_cidrs
        )
    except ValueError:
        trusted = False
    if trusted:
        forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            return peer
    return peer
