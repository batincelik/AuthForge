import asyncio
import json
import os

import httpx
from authforge.database import SessionFactory
from authforge.models import EmailOutbox, RefreshToken, SecurityEvent, Session
from cryptography.fernet import Fernet
from sqlalchemy import select


async def main() -> None:
    base = "http://127.0.0.1:8000"
    email = "security-smoke@example.com"
    password = "correct horse battery staple"
    async with httpx.AsyncClient(base_url=base, headers={"Origin": "http://localhost:3000"}) as client:
        registered = await client.post("/api/v1/auth/register", json={"email": email, "password": password})
        assert registered.status_code in (201, 409), registered.text
        async with SessionFactory() as db:
            row = (await db.execute(select(EmailOutbox).where(EmailOutbox.recipient == email, EmailOutbox.template == "verify_email").order_by(EmailOutbox.created_at.desc()))).scalars().first()
            assert row is not None
            payload = json.loads(Fernet(os.environ["AUTHFORGE_ENCRYPTION_KEY"].encode()).decrypt(row.payload_encrypted.encode()))
        verified = await client.post("/api/v1/auth/verify-email", json={"token": payload["token"]})
        assert verified.status_code in (204, 400), verified.text
        login = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200, login.text
        token_a = login.json()["refresh_token"]
        first = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_a})
        assert first.status_code == 200, first.text
        token_b = first.json()["refresh_token"]
        reuse = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_a})
        assert reuse.status_code == 401 and reuse.json()["error"]["code"] == "REFRESH_TOKEN_REUSED", reuse.text
        family_dead = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_b})
        assert family_dead.status_code == 401, family_dead.text
        async with SessionFactory() as db:
            assert not (await db.execute(select(Session.token_hash).where(Session.token_hash == token_a))).first()
            assert not (await db.execute(select(RefreshToken.token_hash).where(RefreshToken.token_hash == token_a))).first()
            event = (await db.execute(select(SecurityEvent).where(SecurityEvent.event_type == "refresh_token_reuse"))).scalars().first()
            assert event is not None
        second_login = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert second_login.status_code == 200, second_login.text
        concurrent_a = second_login.json()["refresh_token"]

    async def rotate() -> httpx.Response:
        async with httpx.AsyncClient(base_url=base) as racer:
            return await racer.post("/api/v1/auth/refresh", json={"refresh_token": concurrent_a})

    results = await asyncio.gather(rotate(), rotate())
    assert sorted(response.status_code for response in results) == [200, 401]
    winner = next(response for response in results if response.status_code == 200)
    loser = next(response for response in results if response.status_code == 401)
    assert loser.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"
    async with httpx.AsyncClient(base_url=base) as client:
        successor = await client.post("/api/v1/auth/refresh", json={"refresh_token": winner.json()["refresh_token"]})
        assert successor.status_code == 401
    print("security-smoke-ok: rotation, reuse response, concurrent single winner, family revocation, event, and raw-token non-storage")


asyncio.run(main())
