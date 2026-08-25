import asyncio
import re
import sys

import httpx

sys.path.insert(0, "/srv/authforge/apps/worker")
from authforge_worker import tick  # noqa: E402


async def newest_message(recipient: str, subject: str) -> str:
    async with httpx.AsyncClient() as client:
        listing = (await client.get("http://mailpit:8025/api/v1/messages")).json()
        summary = next(
            item
            for item in listing["messages"]
            if recipient in str(item.get("To", item.get("to", "")))
            and subject in str(item.get("Subject", item.get("subject", "")))
        )
        message_id = summary.get("ID", summary.get("id"))
        detail = (await client.get(f"http://mailpit:8025/api/v1/message/{message_id}")).json()
        return "\n".join(str(detail.get(key, "")) for key in ("Text", "HTML", "text", "html"))


async def main() -> None:
    base = "http://127.0.0.1:8000"
    origin = {"Origin": "http://localhost:3000"}
    email = "mail-e2e@example.com"
    old_password = "initial mail e2e passphrase"
    new_password = "rotated mail e2e passphrase"
    async with httpx.AsyncClient(base_url=base, headers=origin) as client:
        registered = await client.post(
            "/api/v1/auth/register", json={"email": email, "password": old_password}
        )
        assert registered.status_code in (201, 409), registered.text
        await tick()
        verification_body = await newest_message(email, "Verify your email")
        verification_token = re.search(r"token=([^\s<]+)", verification_body).group(1)
        verified = await client.post(
            "/api/v1/auth/verify-email", json={"token": verification_token}
        )
        assert verified.status_code in (204, 400), verified.text
        login = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": old_password}
        )
        assert login.status_code == 200, login.text
        old_refresh = login.json()["refresh_token"]
        requested = await client.post("/api/v1/auth/password-reset/request", json={"email": email})
        assert requested.status_code == 200
        await tick()
        reset_body = await newest_message(email, "Reset your password")
        reset_token = re.search(r"token=([^\s<]+)", reset_body).group(1)
        reset = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": new_password},
        )
        assert reset.status_code == 204, reset.text
        assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})).status_code == 401
        assert (await client.post("/api/v1/auth/login", json={"email": email, "password": old_password})).status_code == 401
        assert (await client.post("/api/v1/auth/login", json={"email": email, "password": new_password})).status_code == 200
    print("email-e2e-ok: Mailpit verification link, reset link, password replacement, old session family revocation")


asyncio.run(main())
