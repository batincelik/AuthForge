import asyncio
import os
import uuid

import httpx


async def main() -> None:
    api = os.getenv("AUTHFORGE_TEST_API_URL", "http://127.0.0.1:8000")
    headers = {"Origin": os.getenv("AUTHFORGE_TEST_ORIGIN", "http://localhost:3000")}
    async with httpx.AsyncClient(base_url=api, headers=headers) as admin:
        login = await admin.post(
            "/api/v1/auth/login",
            json={
                "email": "instance-admin@example.com",
                "password": "a genuinely long admin passphrase",
            },
        )
        assert login.status_code == 200, login.text
        suffix = uuid.uuid4().hex[:10]
        application = await admin.post(
            "/api/v1/applications",
            json={
                "name": "API key rotation fixture",
                "slug": f"key-rotation-{suffix}",
                "description": None,
                "application_type": "server",
            },
        )
        assert application.status_code == 201, application.text
        application_id = application.json()["id"]

        async def create_key(name: str) -> dict[str, object]:
            response = await admin.post(
                "/api/v1/api-keys",
                json={
                    "application_id": application_id,
                    "name": name,
                    "scopes": ["applications:read"],
                },
            )
            assert response.status_code == 201, response.text
            return response.json()

        original = await create_key("serial rotation")
        rotated = await admin.post(f"/api/v1/api-keys/{original['id']}/rotate")
        assert rotated.status_code == 201, rotated.text
        assert rotated.json()["secret"] != original["secret"]
        async with httpx.AsyncClient(base_url=api) as service:
            old = await service.get(
                "/api/v1/service/application",
                headers={"Authorization": f"Bearer {original['secret']}"},
            )
            new = await service.get(
                "/api/v1/service/application",
                headers={"Authorization": f"Bearer {rotated.json()['secret']}"},
            )
            assert old.status_code == 401, old.text
            assert new.status_code == 200, new.text

        concurrent = await create_key("concurrent rotation")
        cookies = admin.cookies
        async with (
            httpx.AsyncClient(base_url=api, headers=headers, cookies=cookies) as first,
            httpx.AsyncClient(base_url=api, headers=headers, cookies=cookies) as second,
        ):
            results = await asyncio.gather(
                first.post(f"/api/v1/api-keys/{concurrent['id']}/rotate"),
                second.post(f"/api/v1/api-keys/{concurrent['id']}/rotate"),
            )
        assert sorted(result.status_code for result in results) == [201, 409]
        await admin.delete(f"/api/v1/applications/{application_id}")

    print("api-key-rotation-smoke-ok: old secret revoked, new secret works, concurrent rotate serialized")


asyncio.run(main())
