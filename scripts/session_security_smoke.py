import asyncio
from datetime import UTC, datetime, timedelta

import httpx
from authforge.database import SessionFactory
from authforge.models import Session
from authforge.security import token_hash
from sqlalchemy import select


async def login_client() -> httpx.AsyncClient:
    client = httpx.AsyncClient(base_url="http://127.0.0.1:8000", headers={"Origin": "http://localhost:3000"})
    response = await client.post("/api/v1/auth/login", json={"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"})
    assert response.status_code == 200, response.text
    return client


async def main() -> None:
    first, second = await login_client(), await login_client()
    first_raw = first.cookies.get("authforge_session")
    second_raw = second.cookies.get("authforge_session")
    async with SessionFactory() as db:
        first_row = (await db.execute(select(Session).where(Session.token_hash == token_hash(first_raw)))).scalar_one()
        second_row = (await db.execute(select(Session).where(Session.token_hash == token_hash(second_raw)))).scalar_one()
        assert first_row.token_hash != first_raw and second_row.token_hash != second_raw
        first_id, second_id = first_row.id, second_row.id
    revoked = await first.delete(f"/api/v1/me/sessions/{second_id}")
    assert revoked.status_code == 204
    assert (await second.get("/api/v1/me")).status_code == 401
    assert (await first.get("/api/v1/me")).status_code == 200
    async with SessionFactory() as db:
        row = (await db.execute(select(Session).where(Session.id == first_id))).scalar_one()
        row.last_seen_at = datetime.now(UTC) - timedelta(days=8)
        await db.commit()
    assert (await first.get("/api/v1/me")).status_code == 401
    absolute = await login_client()
    absolute_raw = absolute.cookies.get("authforge_session")
    async with SessionFactory() as db:
        row = (await db.execute(select(Session).where(Session.token_hash == token_hash(absolute_raw)))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    assert (await absolute.get("/api/v1/me")).status_code == 401
    logout_client = await login_client()
    logout_raw = logout_client.cookies.get("authforge_session")
    assert (await logout_client.post("/api/v1/auth/logout")).status_code == 204
    async with SessionFactory() as db:
        row = (await db.execute(select(Session).where(Session.token_hash == token_hash(logout_raw)))).scalar_one()
        assert row.revoked_at is not None
    all_a, all_b = await login_client(), await login_client()
    assert (await all_a.post("/api/v1/auth/logout-all")).status_code == 200
    assert (await all_a.get("/api/v1/me")).status_code == 401
    assert (await all_b.get("/api/v1/me")).status_code == 401
    for client in (first, second, absolute, logout_client, all_a, all_b):
        await client.aclose()
    print("session-security-smoke-ok: hashed storage, device revoke, idle/absolute expiry, logout, logout-all")


asyncio.run(main())
