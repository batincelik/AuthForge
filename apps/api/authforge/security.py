import base64
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import InvalidTokenError

from .config import Settings


def normalize_email(email: str) -> str:
    value = email.strip()
    local, separator, domain = value.rpartition("@")
    if not separator or not local or not domain:
        raise ValueError("invalid email address")
    return f"{local}@{domain.lower()}"


def token_hash(token: str) -> str:
    """Fast SHA-256 is suitable because generated tokens have at least 256 bits of entropy."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def random_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


class PasswordService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
        )
        self._dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))

    def validate(self, password: str) -> None:
        length = len(password)
        if length < self.settings.password_min_length or length > self.settings.password_max_length:
            raise ValueError(
                f"password must contain {self.settings.password_min_length}-"
                f"{self.settings.password_max_length} characters"
            )

    def hash(self, password: str) -> str:
        self.validate(password)
        return self.hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> tuple[bool, str | None]:
        try:
            valid = self.hasher.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False, None
        replacement = self.hasher.hash(password) if self.hasher.check_needs_rehash(stored_hash) else None
        return valid, replacement

    def verify_dummy(self, password: str) -> None:
        try:
            self.hasher.verify(self._dummy_hash, password)
        except VerifyMismatchError:
            pass


def _b64url_uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


@dataclass
class JWTService:
    settings: Settings
    private_key: bytes
    public_key: bytes
    active_kid: str = ""
    verification_keys: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.active_kid:
            self.active_kid = self.settings.jwt_key_id
        if not self.verification_keys:
            self.verification_keys[self.active_kid] = self.public_key

    @classmethod
    def load(cls, settings: Settings) -> "JWTService":
        private_path = Path(settings.jwt_private_key_path)
        public_path = Path(settings.jwt_public_key_path)
        metadata_path = public_path.with_name("jwt-active-kid")
        active_kid = metadata_path.read_text().strip() if metadata_path.exists() else settings.jwt_key_id
        public_key = public_path.read_bytes()
        keys = {active_kid: public_key}
        for historical in public_path.parent.glob("jwt-public-*.pem"):
            kid = historical.name.removeprefix("jwt-public-").removesuffix(".pem")
            keys[kid] = historical.read_bytes()
        return cls(
            settings=settings,
            private_key=private_path.read_bytes(),
            public_key=public_key,
            active_kid=active_kid,
            verification_keys=keys,
        )

    def issue(self, subject: str, session_id: str, scopes: list[str] | None = None) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.settings.jwt_issuer,
            "sub": subject,
            "aud": self.settings.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=self.settings.access_token_ttl_seconds),
            "jti": secrets.token_urlsafe(16),
            "session_id": session_id,
        }
        if scopes is not None:
            claims["scope"] = " ".join(scopes)
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.active_kid, "typ": "JWT"},
        )

    def verify(self, token: str) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str) or kid not in self.verification_keys:
            raise InvalidTokenError("unsupported signing key or algorithm")
        return jwt.decode(
            token,
            self.verification_keys[kid],
            algorithms=["RS256"],
            issuer=self.settings.jwt_issuer,
            audience=self.settings.jwt_audience,
            options={"require": ["exp", "iat", "iss", "sub", "aud", "jti"]},
        )

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        keys: list[dict[str, str]] = []
        for kid, material in self.verification_keys.items():
            public = serialization.load_pem_public_key(material)
            if not isinstance(public, rsa.RSAPublicKey):
                raise TypeError("configured key is not RSA")
            numbers = public.public_numbers()
            keys.append({
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                "n": _b64url_uint(numbers.n), "e": _b64url_uint(numbers.e),
            })
        return {"keys": keys}

    def rotate(self) -> str:
        old_kid = self.active_kid
        public_path = Path(self.settings.jwt_public_key_path)
        private_path = Path(self.settings.jwt_private_key_path)
        archive = public_path.with_name(f"jwt-public-{old_kid}.pem")
        if not archive.exists():
            archive.write_bytes(self.public_key)
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        new_private = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        new_public = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        new_kid = f"key-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"
        private_tmp = private_path.with_suffix(".tmp")
        public_tmp = public_path.with_suffix(".tmp")
        private_tmp.write_bytes(new_private)
        os.chmod(private_tmp, 0o600)
        public_tmp.write_bytes(new_public)
        os.replace(private_tmp, private_path)
        os.replace(public_tmp, public_path)
        public_path.with_name("jwt-active-kid").write_text(new_kid)
        self.private_key, self.public_key, self.active_kid = new_private, new_public, new_kid
        self.verification_keys[old_kid] = self.verification_keys.get(old_kid, archive.read_bytes())
        self.verification_keys[new_kid] = new_public
        return new_kid
