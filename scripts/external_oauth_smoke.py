import asyncio
import os
from datetime import UTC, datetime, timedelta

import httpx
from authforge.database import SessionFactory
from authforge.models import OAuthAccount, OAuthFlowState
from sqlalchemy import select


async def main() -> None:
    api = "http://127.0.0.1:8000"
    origin = {"Origin": "http://localhost:3000"}
    callback = f"{api}/api/v1/oauth/connections/fixture/callback"
    fixture = os.environ.get("OAUTH_FIXTURE_URL", "http://127.0.0.1:9000").rstrip("/")
    admin_credentials = {"email": "instance-admin@example.com", "password": "a genuinely long admin passphrase"}
    async with httpx.AsyncClient(base_url=api, headers=origin, follow_redirects=True) as admin:
        assert (await admin.post("/api/v1/auth/login", json=admin_credentials)).status_code == 200
        connection = await admin.post("/api/v1/oauth/connections", json={"provider": "fixture", "issuer": "http://oauth-fixture:9000", "authorization_endpoint": f"{fixture}/authorize", "token_endpoint": f"{fixture}/token", "jwks_uri": f"{fixture}/.well-known/jwks.json", "client_id": "fixture-client", "scopes": ["openid", "email"]})
        assert connection.status_code in (201, 409), connection.text
        started = await admin.post("/api/v1/oauth/connections/fixture/link/start", json={"redirect_uri": callback})
        assert started.status_code == 200, started.text
        linked = await admin.get(started.json()["authorization_url"])
        assert linked.status_code == 200 and linked.json()["status"] == "linked", linked.text
        callback_url = str(linked.url)
        replay = await admin.get(callback_url)
        assert replay.status_code == 400 and replay.json()["error"]["code"] == "INVALID_OAUTH_STATE"
        mismatch = await admin.get(f"{callback}?state=attacker-state&code=attacker-code")
        assert mismatch.status_code == 400
        expired_start = await admin.post("/api/v1/oauth/connections/fixture/link/start", json={"redirect_uri": callback})
        async with SessionFactory() as db:
            flow = (await db.execute(select(OAuthFlowState).where(OAuthFlowState.state_hash.is_not(None)).order_by(OAuthFlowState.created_at.desc()))).scalars().first()
            flow.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()
        expired = await admin.get(expired_start.json()["authorization_url"])
        assert expired.status_code == 400
    async with httpx.AsyncClient(base_url=api, headers=origin, follow_redirects=True) as other:
        assert (await other.post("/api/v1/auth/login", json={"email": "security-smoke@example.com", "password": "correct horse battery staple"})).status_code == 200
        start = await other.post("/api/v1/oauth/connections/fixture/link/start", json={"redirect_uri": callback})
        conflict = await other.get(start.json()["authorization_url"])
        assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "OAUTH_ACCOUNT_IN_USE"
    async with SessionFactory() as db:
        accounts = (await db.execute(select(OAuthAccount).where(OAuthAccount.provider == "fixture"))).scalars().all()
        assert len(accounts) == 1
    print("external-oauth-smoke-ok: PKCE exchange, state expiry/mismatch/replay, nonce/signature validation, explicit safe linking")


asyncio.run(main())
