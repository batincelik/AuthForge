import asyncio
from datetime import UTC, datetime, timedelta

import httpx
from authforge.database import SessionFactory
from authforge.models import User
from redis.asyncio import Redis
from sqlalchemy import select


async def main() -> None:
    redis = Redis.from_url("redis://redis:6379/0")
    await redis.flushdb()
    base = "http://127.0.0.1:8000"
    email = "mail-e2e@example.com"
    good = "rotated mail e2e passphrase"
    async with httpx.AsyncClient(base_url=base) as client:
        responses = [
            await client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "wrong but sufficiently long password"},
            )
            for _ in range(10)
        ]
        assert all(response.status_code == 401 for response in responses)
        assert (await client.post("/api/v1/auth/login", json={"email": email, "password": good})).status_code == 429
        await redis.flushdb()
        locked = await client.post("/api/v1/auth/login", json={"email": email, "password": good})
        assert locked.status_code == 423
        async with SessionFactory() as db:
            user = (await db.execute(select(User).where(User.email_normalized == email))).scalar_one()
            user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()
        await redis.flushdb()
        valid = await client.post("/api/v1/auth/login", json={"email": email, "password": good})
        assert valid.status_code == 200, valid.text
        async with SessionFactory() as db:
            user = (await db.execute(select(User).where(User.email_normalized == email))).scalar_one()
            assert user.failed_login_count == 0 and user.locked_until is None
    await redis.aclose()
    print("lockout-rate-limit-smoke-ok: bounded account/IP limits, temporary lock, expiry, successful reset")


asyncio.run(main())
