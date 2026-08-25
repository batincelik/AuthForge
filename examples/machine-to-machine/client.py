import os

import httpx

response = httpx.post(
    f"{os.environ['AUTHFORGE_URL']}/api/v1/oauth/token",
    json={
        "grant_type": "client_credentials",
        "client_id": os.environ["AUTHFORGE_CLIENT_ID"],
        "client_secret": os.environ["AUTHFORGE_CLIENT_SECRET"],
    },
    timeout=10,
)
response.raise_for_status()
print(response.json()["access_token"])

