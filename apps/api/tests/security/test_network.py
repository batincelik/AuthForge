from dataclasses import dataclass

from authforge.config import Settings
from authforge.network import client_ip


@dataclass
class Client:
    host: str


@dataclass
class Request:
    client: Client
    headers: dict[str, str]


def test_forwarded_for_is_ignored_from_untrusted_peer() -> None:
    request = Request(Client("203.0.113.10"), {"x-forwarded-for": "1.2.3.4"})
    settings = Settings(authforge_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    assert client_ip(request, settings) == "203.0.113.10"  # type: ignore[arg-type]


def test_forwarded_for_is_used_only_for_configured_proxy() -> None:
    request = Request(Client("10.0.0.2"), {"x-forwarded-for": "198.51.100.8"})
    settings = Settings(authforge_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", trusted_proxy_cidrs=["10.0.0.0/8"])
    assert client_ip(request, settings) == "198.51.100.8"  # type: ignore[arg-type]
