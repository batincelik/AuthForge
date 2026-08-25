from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://authforge:authforge@localhost:5432/authforge"
    redis_url: str = "redis://localhost:6379/0"
    authforge_env: str = "development"
    authforge_encryption_key: str = ""
    dashboard_url: str = "http://localhost:3000"
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    session_cookie_name: str = "authforge_session"
    session_absolute_ttl_seconds: int = 30 * 86400
    session_idle_ttl_seconds: int = 7 * 86400
    session_last_seen_interval_seconds: int = 300
    access_token_ttl_seconds: int = 600
    refresh_token_ttl_seconds: int = 30 * 86400
    jwt_private_key_path: Path = Path("keys/jwt-private.pem")
    jwt_public_key_path: Path = Path("keys/jwt-public.pem")
    jwt_key_id: str = "dev-2026-01"
    jwt_issuer: str = "http://localhost:8000"
    jwt_audience: str = "authforge-api"
    oauth_callback_base_url: str = "http://127.0.0.1:8000"
    password_min_length: int = 12
    password_max_length: int = 1024
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 4
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    login_rate_limit: int = 10
    register_rate_limit: int = 5
    password_reset_rate_limit: int = 5
    refresh_rate_limit: int = 30
    rate_limit_window_seconds: int = 60

    @field_validator("cors_allowed_origins")
    @classmethod
    def no_wildcard_origins(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("credentialed CORS requires explicit origins")
        return value

    @model_validator(mode="after")
    def production_safety(self) -> "Settings":
        if not self.authforge_encryption_key:
            raise ValueError("AUTHFORGE_ENCRYPTION_KEY is required")
        if self.authforge_env == "production" and not self.jwt_issuer.startswith("https://"):
            raise ValueError("production JWT issuer must use HTTPS")
        if self.authforge_env == "production" and not self.session_cookie_name.startswith("__Host-"):
            raise ValueError("production session cookie must use the __Host- prefix")
        return self

    @property
    def secure_cookies(self) -> bool:
        return self.authforge_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
