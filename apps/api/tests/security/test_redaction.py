from authforge.logging_utils import redact


def test_nested_credentials_and_bearers_are_redacted() -> None:
    source = {
        "email": "user@example.com",
        "nested": {"password": "correct horse", "refresh_token": "af_refresh_raw"},
        "message": "received Bearer eyJhbGciOiJub25lIn0.payload.signature",
        "items": ["af_session_stolen", {"client_secret": "secret-value"}],
    }
    result = redact(source)
    assert result["email"] == "user@example.com"
    rendered = repr(result)
    for secret in ("correct horse", "af_refresh_raw", "eyJhbGci", "af_session_stolen", "secret-value"):
        assert secret not in rendered
