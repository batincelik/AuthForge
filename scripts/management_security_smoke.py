import asyncio

import httpx


async def main() -> None:
    api = "http://127.0.0.1:8000"
    origin = {"Origin": "http://localhost:3000"}
    async with httpx.AsyncClient(base_url=api, headers=origin) as admin:
        assert (await admin.post("/api/v1/auth/login", json={"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"})).status_code == 200
        application_id = (await admin.get("/api/v1/applications")).json()[0]["id"]
        invalid_values = [
            {"redirect_uris": ["https://example.com/callback/changed"], "allowed_origins": ["https://example.com/path"]},
            {"redirect_uris": ["http://example.com/callback"], "allowed_origins": ["https://example.com"]},
            {"redirect_uris": ["https://user:pass@example.com/callback"], "allowed_origins": ["https://example.com"]},
        ]
        for index, values in enumerate(invalid_values):
            response = await admin.post(f"/api/v1/applications/{application_id}/environments", json={"name": f"Invalid {index}", "key": f"invalid-{index}", "issuer_url": "https://issuer.example.com", **values})
            assert response.status_code == 400, response.text
        environment = await admin.post(f"/api/v1/applications/{application_id}/environments", json={"name": "Production", "key": "production", "issuer_url": "https://issuer.example.com", "redirect_uris": ["https://app.example.com/callback"], "allowed_origins": ["https://app.example.com"]})
        assert environment.status_code in (201, 409), environment.text
        users = (await admin.get("/api/v1/users")).json()
        target = next(user for user in users if user["email"] == "mail-e2e@example.com")
    async with httpx.AsyncClient(base_url=api, headers=origin) as target_client:
        login = await target_client.post("/api/v1/auth/login", json={"email": target["email"], "password": "rotated mail e2e passphrase"})
        assert login.status_code == 200
        refresh = login.json()["refresh_token"]
        async with httpx.AsyncClient(base_url=api, headers=origin) as admin_actions:
            assert (await admin_actions.post("/api/v1/auth/login", json={"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"})).status_code == 200
            disabled = await admin_actions.post(f"/api/v1/users/{target['id']}/disable")
            assert disabled.status_code == 200 and disabled.json()["status"] == "disabled"
            assert (await target_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})).status_code == 401
            assert (await target_client.post("/api/v1/auth/login", json={"email": target["email"], "password": "rotated mail e2e passphrase"})).status_code == 403
            enabled = await admin_actions.post(f"/api/v1/users/{target['id']}/enable")
            assert enabled.status_code == 200
        assert (await target_client.post("/api/v1/auth/login", json={"email": target["email"], "password": "rotated mail e2e passphrase"})).status_code == 200
    print("management-security-smoke-ok: strict redirect/origin validation, durable disable, session-family revocation, enable")


asyncio.run(main())
