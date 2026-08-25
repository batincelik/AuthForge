from pathlib import Path

import jwt
import pytest
from authforge.config import Settings
from authforge.security import (
    JWTService,
    PasswordService,
    normalize_email,
    random_token,
    token_hash,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_bytes = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_bytes = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_path, public_path = tmp_path / "private.pem", tmp_path / "public.pem"
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    return Settings(authforge_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", jwt_private_key_path=private_path, jwt_public_key_path=public_path, argon2_memory_cost_kib=8192, argon2_time_cost=1, argon2_parallelism=1)


def test_argon2id_hash_rehash_and_limits(settings: Settings) -> None:
    service = PasswordService(settings)
    encoded = service.hash("a sufficiently long passphrase")
    assert encoded.startswith("$argon2id$")
    assert "sufficiently long passphrase" not in encoded
    assert service.verify(encoded, "a sufficiently long passphrase")[0]
    assert not service.verify(encoded, "the wrong long password")[0]
    with pytest.raises(ValueError):
        service.hash("short")


def test_email_normalization_is_conservative() -> None:
    assert normalize_email(" User.Name+tag@EXAMPLE.COM ") == "User.Name+tag@example.com"


def test_random_tokens_are_hashed_not_reversible() -> None:
    raw = random_token("af_test")
    digest = token_hash(raw)
    assert raw not in digest and len(digest) == 64


def test_jwt_claims_jwks_and_algorithm_allowlist(settings: Settings) -> None:
    service = JWTService.load(settings)
    token = service.issue("user-id", "session-id")
    claims = service.verify(token)
    assert claims["iss"] == settings.jwt_issuer and claims["aud"] == settings.jwt_audience
    assert service.jwks()["keys"][0]["kid"] == settings.jwt_key_id
    none_token = jwt.encode({"sub": "attacker"}, key="", algorithm="none", headers={"kid": settings.jwt_key_id})
    with pytest.raises(jwt.InvalidTokenError):
        service.verify(none_token)
    header, payload, signature = token.split(".")
    wrong_kid = jwt.encode(jwt.decode(token, options={"verify_signature": False}), service.private_key, algorithm="RS256", headers={"kid": "unknown"})
    with pytest.raises(jwt.InvalidTokenError):
        service.verify(wrong_kid)
    with pytest.raises(jwt.InvalidTokenError):
        service.verify(f"{header}.{payload}.{signature[:-2]}aa")
