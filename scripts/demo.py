import os

import httpx

base = os.environ.get("AUTHFORGE_URL", "http://localhost:8000")
email = os.environ.get("AUTHFORGE_DEMO_ADMIN_EMAIL", "admin@demo.authforge.local")
password = os.environ.get("AUTHFORGE_DEMO_ADMIN_PASSWORD", "development-only demo passphrase")
headers = {"Origin": os.environ.get("DASHBOARD_URL", "http://localhost:3000")}
with httpx.Client(base_url=base, headers=headers, timeout=15) as client:
    setup = client.post(
        "/api/v1/setup",
        json={"email": email, "password": password, "instance_name": "AuthForge Demo"},
    )
    if setup.status_code not in (201, 409):
        setup.raise_for_status()
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    login.raise_for_status()
    application = client.post(
        "/api/v1/applications",
        json={"name": "Demo application", "slug": "demo-application", "application_type": "web"},
    )
    if application.status_code not in (201, 409):
        application.raise_for_status()
    organization = client.post(
        "/api/v1/organizations", json={"name": "Demo organization", "slug": "demo-organization"}
    )
    if organization.status_code not in (201, 409):
        organization.raise_for_status()
print("Demo data created through AuthForge's real setup, authentication, and authorization APIs.")
