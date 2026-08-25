import asyncio
import os
import uuid

import httpx


async def main() -> None:
    suffix = uuid.uuid4().hex[:10]
    headers = {"Origin": os.getenv("AUTHFORGE_TEST_ORIGIN", "http://localhost:3000")}
    async with httpx.AsyncClient(
        base_url=os.getenv("AUTHFORGE_TEST_API_URL", "http://127.0.0.1:8000"), headers=headers
    ) as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "instance-admin@example.com",
                "password": "a genuinely long admin passphrase",
            },
        )
        assert login.status_code == 200, login.text

        created = await client.post(
            "/api/v1/applications",
            json={
                "name": "CRUD fixture",
                "slug": f"crud-{suffix}",
                "description": None,
                "application_type": "web",
            },
        )
        assert created.status_code == 201, created.text
        application_id = created.json()["id"]

        updated = await client.patch(
            f"/api/v1/applications/{application_id}",
            json={"name": "Updated CRUD fixture", "description": "durable"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["description"] == "durable"
        assert (await client.patch(f"/api/v1/applications/{application_id}", json={})).status_code == 422

        environment = await client.post(
            f"/api/v1/applications/{application_id}/environments",
            json={
                "name": "Development",
                "key": "development",
                "issuer_url": "https://issuer.example.test",
                "redirect_uris": ["https://client.example.test/callback"],
                "allowed_origins": ["https://client.example.test"],
            },
        )
        assert environment.status_code == 201, environment.text
        environment_id = environment.json()["id"]
        changed_environment = await client.patch(
            f"/api/v1/applications/{application_id}/environments/{environment_id}",
            json={"redirect_uris": ["https://client.example.test/new-callback"]},
        )
        assert changed_environment.status_code == 200, changed_environment.text

        other = await client.post(
            "/api/v1/applications",
            json={
                "name": "Other fixture",
                "slug": f"other-{suffix}",
                "description": None,
                "application_type": "web",
            },
        )
        assert other.status_code == 201, other.text
        other_id = other.json()["id"]
        cross_application = await client.patch(
            f"/api/v1/applications/{other_id}/environments/{environment_id}",
            json={"name": "Cross-application write"},
        )
        assert cross_application.status_code == 404, cross_application.text

        assert (await client.delete(f"/api/v1/applications/{application_id}")).status_code == 204
        assert (await client.get(f"/api/v1/applications/{application_id}")).status_code == 404
        assert (await client.delete(f"/api/v1/applications/{other_id}")).status_code == 204

    print("application-crud-smoke-ok: update/delete, exact URI validation, cross-application isolation")


asyncio.run(main())
