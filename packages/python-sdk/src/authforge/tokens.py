from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

import httpx
import jwt


class JWKSVerifier:
    def __init__(self, issuer: str, audience: str, cache_ttl: int = 300, timeout: float = 5.0) -> None:
        self.issuer, self.audience = issuer.rstrip("/"), audience
        self.cache_ttl, self.timeout = cache_ttl, timeout
        self._jwks: dict[str, Any] | None = None
        self._expires_at = datetime.min.replace(tzinfo=UTC)
        self._lock = Lock()

    def _load(self, force: bool = False) -> dict[str, Any]:
        with self._lock:
            if force or self._jwks is None or datetime.now(UTC) >= self._expires_at:
                response = httpx.get(f"{self.issuer}/.well-known/jwks.json", timeout=self.timeout)
                response.raise_for_status()
                self._jwks = dict(response.json())
                self._expires_at = datetime.now(UTC) + timedelta(seconds=self.cache_ttl)
            return self._jwks

    def verify(self, token: str) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise jwt.InvalidTokenError("unsupported JWT algorithm or missing kid")
        for force in (False, True):
            jwks = self._load(force)
            key = next((item for item in jwks.get("keys", []) if item.get("kid") == header["kid"] and item.get("alg") == "RS256"), None)
            if key is not None:
                return dict(jwt.decode(token, jwt.PyJWK(key).key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience, options={"require": ["exp", "iat", "iss", "sub", "aud", "jti"]}))
        raise jwt.InvalidTokenError("unknown signing key")
