import asyncio

import httpx
from authforge.config import get_settings
from authforge.security import JWTService


async def main() -> None:
    base = "http://127.0.0.1:8000"
    headers = {"Origin": "http://localhost:3000"}
    credentials = {"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"}
    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
        before = await client.post("/api/v1/auth/login", json=credentials)
        assert before.status_code == 200, before.text
        old_token = before.json()["access_token"]
        old_kid = JWTService.load(get_settings()).verify(old_token)
        rotated = await client.post("/api/v1/signing-keys/rotate")
        assert rotated.status_code == 200, rotated.text
        after = await client.post("/api/v1/auth/login", json=credentials)
        assert after.status_code == 200, after.text
        new_token = after.json()["access_token"]
        verifier = JWTService.load(get_settings())
        assert verifier.verify(old_token)["sub"] == old_kid["sub"]
        assert verifier.verify(new_token)["sub"] == old_kid["sub"]
        kids = {key["kid"] for key in (await client.get("/.well-known/jwks.json")).json()["keys"]}
        assert rotated.json()["previous_kid"] in kids and rotated.json()["kid"] in kids
    print(f"key-rotation-smoke-ok: {rotated.json()['previous_kid']} -> {rotated.json()['kid']}, old/new verification and JWKS overlap")


asyncio.run(main())
