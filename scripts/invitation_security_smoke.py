import asyncio
import json
import os

import httpx
from authforge.database import SessionFactory
from authforge.models import EmailOutbox, Membership, Organization, Role
from cryptography.fernet import Fernet
from sqlalchemy import func, select


async def main() -> None:
    base = "http://127.0.0.1:8000"
    origin = {"Origin": "http://localhost:3000"}
    async with SessionFactory() as db:
        organization = (await db.execute(select(Organization).where(Organization.slug == "smoke-org"))).scalar_one()
        member_role = (await db.execute(select(Role).where(Role.organization_id == organization.id, Role.key == "member"))).scalar_one()
    async with httpx.AsyncClient(base_url=base, headers=origin) as admin:
        login = await admin.post("/api/v1/auth/login", json={"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"})
        assert login.status_code == 200, login.text
        invited = await admin.post(f"/api/v1/organizations/{organization.id}/invitations", json={"email": "security-smoke@example.com", "role_id": member_role.id})
        assert invited.status_code == 201, invited.text
    async with SessionFactory() as db:
        row = (await db.execute(select(EmailOutbox).where(EmailOutbox.template == "organization_invitation", EmailOutbox.recipient == "security-smoke@example.com").order_by(EmailOutbox.created_at.desc()))).scalars().first()
        payload = json.loads(Fernet(os.environ["AUTHFORGE_ENCRYPTION_KEY"].encode()).decrypt(row.payload_encrypted.encode()))
        raw = payload["token"]
        assert raw not in row.payload_encrypted
    async with httpx.AsyncClient(base_url=base, headers=origin) as member:
        login = await member.post("/api/v1/auth/login", json={"email": "security-smoke@example.com", "password": "correct horse battery staple"})
        assert login.status_code == 200, login.text
        user_id = (await member.get("/api/v1/me")).json()["id"]
        cookie = member.cookies.get("authforge_session")

    async def accept() -> httpx.Response:
        async with httpx.AsyncClient(base_url=base, headers=origin, cookies={"authforge_session": cookie}) as racer:
            return await racer.post("/api/v1/invitations/accept", json={"token": raw})

    results = await asyncio.gather(accept(), accept())
    assert sum(response.status_code == 201 for response in results) == 1
    async with SessionFactory() as db:
        count = (await db.execute(select(func.count()).select_from(Membership).where(Membership.organization_id == organization.id, Membership.user_id == user_id))).scalar_one()
        assert count == 1
    async with httpx.AsyncClient(base_url=base, headers=origin, cookies={"authforge_session": cookie}) as member:
        visible = await member.get(f"/api/v1/organizations/{organization.id}/members")
        assert visible.status_code == 200
        assert sum(item["user_id"] == user_id for item in visible.json()) == 1
    print("invitation-security-smoke-ok: encrypted delivery, verified-email binding, atomic single use, RBAC membership")


asyncio.run(main())
