from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    instance_name: str = Field(min_length=1, max_length=120)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class PurposeTokenRequest(BaseModel):
    token: str


class ResetRequest(BaseModel):
    email: EmailStr


class ResetConfirmRequest(BaseModel):
    token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class VerificationResendRequest(BaseModel):
    email: EmailStr


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    email_verified_at: datetime | None
    display_name: str | None
    status: str


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    ip_address: str | None
    user_agent: str | None
    device_name: str | None
    current: bool = False


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$")
    description: str | None = Field(default=None, max_length=500)
    application_type: str = Field(pattern=r"^(web|spa|mobile|server|machine)$")


class ApplicationResponse(ApplicationCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str


class ApplicationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$")
    description: str | None = Field(default=None, max_length=500)
    application_type: str | None = Field(default=None, pattern=r"^(web|spa|mobile|server|machine)$")


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$")


class OrganizationResponse(OrganizationCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str


class ApiKeyCreate(BaseModel):
    application_id: str
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=50)
    expires_at: datetime | None = None


class ApiKeyCreated(BaseModel):
    id: str
    secret: str
    prefix: str
    scopes: list[str]


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    application_id: str
    name: str
    prefix: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None


class MembershipRoleUpdate(BaseModel):
    role_id: str


class MachineClientCreate(BaseModel):
    application_id: str
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=50)


class MachineClientCreated(BaseModel):
    id: str
    client_id: str
    client_secret: str
    scopes: list[str]


class ClientCredentialsRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str


class MachineTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


class OAuthClientCreate(BaseModel):
    application_id: str
    redirect_uris: list[str] = Field(min_length=1, max_length=20)
    scopes: list[str] = Field(min_length=1, max_length=50)
    public: bool = True


class OAuthClientCreated(BaseModel):
    id: str
    client_id: str
    client_secret: str | None
    redirect_uris: list[str]


class AuthorizationRequest(BaseModel):
    client_id: str
    redirect_uri: str
    state: str = Field(min_length=16, max_length=512)
    code_challenge: str = Field(min_length=43, max_length=128)
    code_challenge_method: str
    scope: str = "openid"


class AuthorizationResponse(BaseModel):
    code: str
    state: str
    redirect_uri: str


class AuthorizationCodeTokenRequest(BaseModel):
    grant_type: str
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str = Field(min_length=43, max_length=128)
    client_secret: str | None = None


class InvitationCreate(BaseModel):
    email: EmailStr
    role_id: str


class InvitationCreated(BaseModel):
    id: str
    email: str
    expires_at: datetime


class InvitationAccept(BaseModel):
    token: str


class OAuthConnectionCreate(BaseModel):
    provider: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,78}[a-z0-9]$")
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    client_id: str
    scopes: list[str] = Field(min_length=1, max_length=20)


class OAuthLinkStart(BaseModel):
    redirect_uri: str


class OAuthLinkCallback(BaseModel):
    state: str
    code: str
    redirect_uri: str


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,78}[a-z0-9]$")
    issuer_url: str
    redirect_uris: list[str] = Field(default_factory=list, max_length=50)
    allowed_origins: list[str] = Field(default_factory=list, max_length=50)


class EnvironmentResponse(EnvironmentCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    application_id: str


class EnvironmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    key: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,78}[a-z0-9]$")
    issuer_url: str | None = None
    redirect_uris: list[str] | None = Field(default=None, max_length=50)
    allowed_origins: list[str] | None = Field(default=None, max_length=50)
