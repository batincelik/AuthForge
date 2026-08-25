import asyncio
import base64
import hashlib

import httpx


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


async def main() -> None:
    base = "http://127.0.0.1:8000"
    headers = {"Origin": "http://localhost:3000"}
    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
        login = await client.post("/api/v1/auth/login", json={"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"})
        assert login.status_code == 200, login.text
        application_id = (await client.get("/api/v1/applications")).json()[0]["id"]
        created = await client.post("/api/v1/oauth/clients", json={"application_id": application_id, "redirect_uris": ["http://localhost:4100/callback"], "scopes": ["openid", "profile"], "public": True})
        assert created.status_code == 201, created.text
        client_id = created.json()["client_id"]
        verifier = "v" * 64
        authorization = {"client_id": client_id, "redirect_uri": "http://localhost:4100/callback", "state": "state-with-at-least-16-chars", "code_challenge": challenge(verifier), "code_challenge_method": "S256", "scope": "openid profile"}
        for changed in ("https://localhost:4100/callback", "http://evil.localhost:4100/callback", "http://localhost:4200/callback", "http://localhost:4100/other"):
            invalid = await client.post("/api/v1/oauth/authorize", json={**authorization, "redirect_uri": changed})
            assert invalid.status_code == 400, invalid.text
        issued = await client.post("/api/v1/oauth/authorize", json=authorization)
        assert issued.status_code == 200 and issued.json()["state"] == authorization["state"], issued.text
        code = issued.json()["code"]
        token_payload = {"grant_type": "authorization_code", "code": code, "client_id": client_id, "redirect_uri": authorization["redirect_uri"], "code_verifier": verifier}
        wrong_client = await client.post("/api/v1/oauth/code-token", json={**token_payload, "client_id": "unknown"})
        assert wrong_client.status_code == 400
        wrong_redirect = await client.post("/api/v1/oauth/code-token", json={**token_payload, "redirect_uri": "http://localhost:4100/other"})
        assert wrong_redirect.status_code == 400
        wrong_verifier = await client.post("/api/v1/oauth/code-token", json={**token_payload, "code_verifier": "x" * 64})
        assert wrong_verifier.status_code == 400
        token = await client.post("/api/v1/oauth/code-token", json=token_payload)
        assert token.status_code == 200, token.text
        replay = await client.post("/api/v1/oauth/code-token", json=token_payload)
        assert replay.status_code == 400
        discovery = await client.get("/.well-known/openid-configuration")
        assert discovery.status_code == 200 and discovery.json()["code_challenge_methods_supported"] == ["S256"]
    print("oidc-security-smoke-ok: exact redirects, state echo, PKCE S256, client/redirect binding, single-use code, discovery")


asyncio.run(main())
