import asyncio

import httpx
from authforge.database import SessionFactory
from authforge.models import ApiKey, AuditEvent
from authforge.security import token_hash
from sqlalchemy import select


async def main() -> None:
    base = "http://127.0.0.1:8000"
    origin = {"Origin": "http://localhost:3000"}
    admin_email = "instance-admin@example.com"
    password = "a genuinely long admin passphrase"
    async with httpx.AsyncClient(base_url=base, headers=origin) as admin:
        setup = await admin.post("/api/v1/setup", json={"email": admin_email, "password": password, "instance_name": "AuthForge"})
        assert setup.status_code in (201, 409), setup.text
        login = await admin.post("/api/v1/auth/login", json={"email": admin_email, "password": password})
        assert login.status_code == 200, login.text
        application = await admin.post("/api/v1/applications", json={"name": "Smoke App", "slug": "smoke-app", "application_type": "web"})
        if application.status_code == 409:
            application_id = (await admin.get("/api/v1/applications")).json()[0]["id"]
        else:
            assert application.status_code == 201, application.text
            application_id = application.json()["id"]
        organization = await admin.post("/api/v1/organizations", json={"name": "Smoke Org", "slug": "smoke-org"})
        assert organization.status_code in (201, 409), organization.text
        key = await admin.post("/api/v1/api-keys", json={"application_id": application_id, "name": "Smoke Key", "scopes": ["users:read"]})
        assert key.status_code == 201, key.text
        raw_key = key.json()["secret"]
        key_id = key.json()["id"]
        async with SessionFactory() as db:
            stored = (await db.execute(select(ApiKey).where(ApiKey.id == key_id))).scalar_one()
            assert stored.key_hash == token_hash(raw_key)
            assert stored.key_hash != raw_key
            assert (await db.execute(select(AuditEvent).where(AuditEvent.action == "api_key_created"))).first()
        revoked = await admin.delete(f"/api/v1/api-keys/{key_id}")
        assert revoked.status_code == 204, revoked.text
        rejected = await admin.get("/api/v1/service/application", headers={"Authorization": f"Bearer {raw_key}"})
        assert rejected.status_code == 401

        scoped = await admin.post("/api/v1/api-keys", json={"application_id": application_id, "name": "Scoped Key", "scopes": ["applications:read"]})
        assert scoped.status_code == 201, scoped.text
        scoped_raw = scoped.json()["secret"]
        allowed = await admin.get("/api/v1/service/application", headers={"Authorization": f"Bearer {scoped_raw}"})
        assert allowed.status_code == 200 and allowed.json()["id"] == application_id, allowed.text
        insufficient = await admin.post("/api/v1/api-keys", json={"application_id": application_id, "name": "Wrong Scope", "scopes": ["users:read"]})
        denied = await admin.get("/api/v1/service/application", headers={"Authorization": f"Bearer {insufficient.json()['secret']}"})
        assert denied.status_code == 403

        machine = await admin.post("/api/v1/machine-clients", json={"application_id": application_id, "name": "CI", "scopes": ["applications:read"]})
        assert machine.status_code == 201, machine.text
        credentials = await admin.post("/api/v1/oauth/token", json={"grant_type": "client_credentials", "client_id": machine.json()["client_id"], "client_secret": machine.json()["client_secret"]})
        assert credentials.status_code == 200 and "refresh_token" not in credentials.json(), credentials.text

    async with httpx.AsyncClient(base_url=base, headers=origin) as ordinary:
        login = await ordinary.post("/api/v1/auth/login", json={"email": "security-smoke@example.com", "password": "correct horse battery staple"})
        assert login.status_code == 200, login.text
        forbidden = await ordinary.get("/api/v1/applications")
        assert forbidden.status_code == 403, forbidden.text
    print("tenant-security-smoke-ok: admin separation, tenant RBAC, scoped/revoked hashed API keys, machine credentials")


asyncio.run(main())
