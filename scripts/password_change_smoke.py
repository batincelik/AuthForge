import asyncio

import httpx


async def main() -> None:
    base = "http://127.0.0.1:8000"
    headers = {"Origin": "http://localhost:3000"}
    email = "instance-admin@example.com"
    old = "a genuinely long admin passphrase"
    new = "a rotated genuinely long admin passphrase"
    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
        login = await client.post("/api/v1/auth/login", json={"email": email, "password": old})
        assert login.status_code == 200, login.text
        old_refresh = login.json()["refresh_token"]
        old_cookie = client.cookies.get("authforge_session")
        changed = await client.post("/api/v1/auth/change-password", json={"current_password": old, "new_password": new})
        assert changed.status_code == 200, changed.text
        assert client.cookies.get("authforge_session") != old_cookie
        stale = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert stale.status_code == 401
        old_login = await httpx.AsyncClient(base_url=base).post("/api/v1/auth/login", json={"email": email, "password": old})
        assert old_login.status_code == 401
        restored = await client.post("/api/v1/auth/change-password", json={"current_password": new, "new_password": old})
        assert restored.status_code == 200, restored.text
    print("password-change-smoke-ok: credential update, session rotation, old refresh revocation, old password rejection")


asyncio.run(main())
