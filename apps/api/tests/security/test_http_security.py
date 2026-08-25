from authforge.main import app, settings
from fastapi.testclient import TestClient


def test_cookie_authenticated_cross_origin_mutation_is_rejected() -> None:
    with TestClient(app) as client:
        client.cookies.set(settings.session_cookie_name, "stolen-cookie")
        forged = client.post("/api/v1/auth/logout", headers={"Origin": "https://evil.example"})
        assert forged.status_code == 403
        assert forged.json()["error"]["code"] == "CSRF_REJECTED"


def test_credentialed_cors_is_explicit() -> None:
    with TestClient(app) as client:
        allowed = client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": settings.cors_allowed_origins[0],
                "Access-Control-Request-Method": "POST",
            },
        )
        assert allowed.headers["access-control-allow-origin"] == settings.cors_allowed_origins[0]
        assert allowed.headers["access-control-allow-credentials"] == "true"
        denied = client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert "access-control-allow-origin" not in denied.headers


def test_security_headers_and_request_id() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-request-id"].startswith("req_")
