import re
from collections.abc import Mapping, Sequence
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "authorization",
        "cookie",
        "set-cookie",
        "access_token",
        "refresh_token",
        "session_token",
        "api_key",
        "client_secret",
        "reset_token",
        "verification_token",
        "token",
        "secret",
        "private_key",
    }
)
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
AUTHFORGE_SECRET_PATTERN = re.compile(
    r"\baf_(?:session|refresh|reset|verify|invite|live|client_secret|oauth_state|code)_[A-Za-z0-9._~-]+"
)


def redact(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower().replace("_hash", "") in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return AUTHFORGE_SECRET_PATTERN.sub(
            "[REDACTED]", BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        )
    return value

