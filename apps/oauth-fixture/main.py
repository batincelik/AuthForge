import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

app = FastAPI(title="AuthForge deterministic OIDC fixture")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
issuer = "http://oauth-fixture:9000"
kid = "fixture-key"
codes: dict[str, dict[str, str | bool]] = {}


def b64int(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


@app.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    code_challenge_method: str,
) -> RedirectResponse:
    if client_id != "fixture-client" or code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="invalid request")
    if redirect_uri != "http://127.0.0.1:8000/api/v1/oauth/connections/fixture/callback":
        raise HTTPException(status_code=400, detail="invalid redirect")
    code = secrets.token_urlsafe(32)
    codes[code] = {
        "challenge": code_challenge,
        "nonce": nonce,
        "redirect_uri": redirect_uri,
        "used": False,
    }
    return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}")


class TokenRequest(BaseModel):
    grant_type: str
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str


@app.post("/token")
async def token(payload: TokenRequest) -> dict[str, object]:
    record = codes.get(payload.code)
    if (
        record is None
        or record["used"] is True
        or payload.grant_type != "authorization_code"
        or payload.client_id != "fixture-client"
        or payload.redirect_uri != record["redirect_uri"]
    ):
        raise HTTPException(status_code=400, detail="invalid grant")
    calculated = base64.urlsafe_b64encode(
        hashlib.sha256(payload.code_verifier.encode()).digest()
    ).rstrip(b"=").decode()
    if not secrets.compare_digest(calculated, str(record["challenge"])):
        raise HTTPException(status_code=400, detail="invalid verifier")
    record["used"] = True
    now = datetime.now(UTC)
    id_token = jwt.encode(
        {
            "iss": issuer,
            "aud": payload.client_id,
            "sub": "fixture-user-001",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "nonce": record["nonce"],
            "email": "fixture-user@example.com",
            "email_verified": True,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return {"access_token": secrets.token_urlsafe(24), "token_type": "Bearer", "expires_in": 300, "id_token": id_token}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict[str, object]:
    numbers = public_key.public_numbers()
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": b64int(numbers.n), "e": b64int(numbers.e)}]}
