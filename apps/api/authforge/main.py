import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from cryptography.fernet import Fernet
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .authorization import AuthorizationService
from .config import get_settings
from .database import get_db
from .logging_utils import redact
from .models import (
    ApiKey,
    Application,
    ApplicationEnvironment,
    AuditEvent,
    AuthorizationCode,
    InstanceAdmin,
    MachineClient,
    Membership,
    OAuthAccount,
    OAuthClient,
    OAuthConnection,
    OAuthFlowState,
    Organization,
    Permission,
    Role,
    RolePermission,
    SecurityEvent,
    Session,
    User,
)
from .network import client_ip
from .rate_limit import RateLimiter
from .schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyResponse,
    ApplicationCreate,
    ApplicationResponse,
    ApplicationUpdate,
    AuthorizationCodeTokenRequest,
    AuthorizationRequest,
    AuthorizationResponse,
    ChangePasswordRequest,
    ClientCredentialsRequest,
    EnvironmentCreate,
    EnvironmentResponse,
    EnvironmentUpdate,
    InvitationAccept,
    InvitationCreate,
    InvitationCreated,
    LoginRequest,
    MachineClientCreate,
    MachineClientCreated,
    MachineTokenResponse,
    MembershipRoleUpdate,
    OAuthClientCreate,
    OAuthClientCreated,
    OAuthConnectionCreate,
    OAuthLinkStart,
    OrganizationCreate,
    OrganizationResponse,
    PurposeTokenRequest,
    RefreshRequest,
    RegisterRequest,
    ResetConfirmRequest,
    ResetRequest,
    SessionResponse,
    SetupRequest,
    TokenResponse,
    UserResponse,
    VerificationResendRequest,
)
from .security import JWTService, PasswordService, random_token, token_hash
from .services import AuthError, AuthService


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    app.state.auth = AuthService(settings, PasswordService(settings), JWTService.load(settings))
    app.state.rate_limiter = RateLimiter(settings)
    yield
    await app.state.rate_limiter.close()


app = FastAPI(title="AuthForge", version="0.1.0", lifespan=lifespan)
settings = get_settings()
authorization = AuthorizationService()
logger = logging.getLogger("authforge.request")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)


@app.middleware("http")
async def security_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    started = time.perf_counter()
    request_id = request.headers.get("x-request-id", f"req_{uuid.uuid4().hex}")[:96]
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.cookies.get(settings.session_cookie_name):
        origin = request.headers.get("origin")
        if origin not in settings.cors_allowed_origins:
            return JSONResponse(status_code=403, content={"error": {"code": "CSRF_REJECTED", "message": "Request origin rejected.", "request_id": request_id}})
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    logger.info(
        json.dumps(
            redact(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            ),
            separators=(",", ":"),
        )
    )
    return response


@app.exception_handler(AuthError)
async def auth_error(request: Request, exc: AuthError) -> JSONResponse:
    request_id = request.headers.get("x-request-id", "unknown")
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message, "request_id": request_id}})


def auth_service(request: Request) -> AuthService:
    return cast(AuthService, request.app.state.auth)


async def enforce_limit(
    request: Request, action: str, dimensions: list[str], limit: int
) -> None:
    limiter = cast(RateLimiter, request.app.state.rate_limiter)
    result = await limiter.check(action, dimensions, limit)
    if not result.allowed:
        raise AuthError(
            "RATE_LIMITED",
            f"Too many requests. Retry after {result.retry_after} seconds.",
            429,
        )


async def current_session(
    request: Request,
    session_cookie: str | None = Cookie(default=None, alias=settings.session_cookie_name),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> Session:
    if not session_cookie:
        raise AuthError("SESSION_EXPIRED", "Authentication required.", 401)
    return await service.authenticate_session(db, session_cookie)


async def current_admin(
    session: Session = Depends(current_session), db: AsyncSession = Depends(get_db)
) -> Session:
    admin = (
        await db.execute(select(InstanceAdmin.id).where(InstanceAdmin.user_id == session.user_id))
    ).scalar_one_or_none()
    if admin is None:
        raise AuthError("PERMISSION_DENIED", "Administrator access required.", 403)
    return session


async def api_key_principal(
    authorization_header: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> ApiKey:
    if not authorization_header or not authorization_header.startswith("Bearer af_live_"):
        raise AuthError("API_KEY_INVALID", "API key is invalid.", 401)
    raw = authorization_header.removeprefix("Bearer ")
    pieces = raw.split("_", 3)
    if len(pieces) != 4:
        raise AuthError("API_KEY_INVALID", "API key is invalid.", 401)
    prefix = "_".join(pieces[:3])
    item = (await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))).scalar_one_or_none()
    now = datetime.now(UTC)
    if (
        item is None
        or item.revoked_at is not None
        or (item.expires_at is not None and item.expires_at <= now)
        or not hmac.compare_digest(item.key_hash, token_hash(raw))
    ):
        raise AuthError("API_KEY_INVALID", "API key is invalid.", 401)
    if item.last_used_at is None or item.last_used_at + timedelta(minutes=5) <= now:
        item.last_used_at = now
        await db.commit()
    return item


def require_api_scope(required: str) -> Callable[..., Awaitable[ApiKey]]:
    async def dependency(key: ApiKey = Depends(api_key_principal)) -> ApiKey:
        if required not in key.scopes:
            raise AuthError("PERMISSION_DENIED", "API key scope is insufficient.", 403)
        return key
    return dependency


def validated_redirect_uri(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.fragment or parsed.username or parsed.password:
        raise AuthError("INVALID_REDIRECT_URI", "Redirect URI is invalid.", 400)
    localhost = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not parsed.hostname or (parsed.scheme != "https" and not (localhost and parsed.scheme == "http")):
        raise AuthError("INVALID_REDIRECT_URI", "Redirect URI is invalid.", 400)
    return uri


def validated_origin(origin: str) -> str:
    parsed = urlparse(origin)
    localhost = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or (parsed.scheme != "https" and not (localhost and parsed.scheme == "http"))
    ):
        raise AuthError("INVALID_ORIGIN", "Allowed origin is invalid.", 400)
    return origin.rstrip("/")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
async def ready(request: Request, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    await db.execute(text("SELECT 1"))
    limiter = cast(RateLimiter, request.app.state.rate_limiter)
    await limiter.redis.ping()
    return {"status": "ready"}


@app.get("/.well-known/jwks.json")
async def jwks(request: Request) -> dict[str, list[dict[str, str]]]:
    return auth_service(request).jwt.jwks()


@app.post("/api/v1/signing-keys/rotate")
async def rotate_signing_key(
    request: Request,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    service = auth_service(request)
    old_kid = service.jwt.active_kid
    new_kid = service.jwt.rotate()
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="signing_key_rotated",
            target_type="signing_key",
            target_id=new_kid,
            metadata_json={"previous_kid": old_kid},
        )
    )
    await db.commit()
    return {"kid": new_kid, "previous_kid": old_kid}


@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201)
async def register(payload: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> UserResponse:
    request_ip = client_ip(request, settings) or "unknown"
    # Account and network dimensions are independently bounded.
    await enforce_limit(request, "register", [request_ip], settings.register_rate_limit)
    user = await service.register(db, str(payload.email), payload.password, payload.display_name)
    return UserResponse.model_validate(user)


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> TokenResponse:
    ip = client_ip(request, settings)
    await enforce_limit(request, "login-ip", [ip or "unknown"], settings.login_rate_limit * 5)
    await enforce_limit(request, "login-account", [str(payload.email).strip().lower()], settings.login_rate_limit)
    issued = await service.login(db, str(payload.email), payload.password, ip, request.headers.get("user-agent"))
    response.set_cookie(settings.session_cookie_name, issued.session_token, max_age=settings.session_absolute_ttl_seconds, httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return TokenResponse(access_token=issued.access_token, refresh_token=issued.refresh_token, expires_in=settings.access_token_ttl_seconds)


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> TokenResponse:
    await enforce_limit(request, "refresh", [client_ip(request, settings) or "unknown"], settings.refresh_rate_limit)
    access, refresh_token = await service.refresh(db, payload.refresh_token)
    return TokenResponse(access_token=access, refresh_token=refresh_token, expires_in=settings.access_token_ttl_seconds)


@app.post("/api/v1/auth/logout", status_code=204)
async def logout(response: Response, session_cookie: str | None = Cookie(default=None, alias=settings.session_cookie_name), db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> None:
    if session_cookie:
        session = await service.authenticate_session(db, session_cookie)
        await service.revoke_session(db, session)
    response.delete_cookie(settings.session_cookie_name, path="/", secure=settings.secure_cookies, httponly=True, samesite="lax")


@app.post("/api/v1/auth/verify-email", status_code=204)
async def verify_email(payload: PurposeTokenRequest, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> None:
    await service.verify_email(db, payload.token)


@app.post("/api/v1/auth/password-reset/request")
async def reset_request(payload: ResetRequest, request: Request, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> dict[str, str]:
    await enforce_limit(request, "password-reset", [client_ip(request, settings) or "unknown"], settings.password_reset_rate_limit)
    await service.request_reset(db, str(payload.email))
    return {"message": "If an account exists, reset instructions have been sent."}


@app.post("/api/v1/auth/password-reset/confirm", status_code=204)
async def reset_confirm(payload: ResetConfirmRequest, db: AsyncSession = Depends(get_db), service: AuthService = Depends(auth_service)) -> None:
    await service.confirm_reset(db, payload.token, payload.new_password)


@app.post("/api/v1/auth/change-password", response_model=TokenResponse)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    current: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> TokenResponse:
    issued = await service.change_password(
        db,
        current,
        payload.current_password,
        payload.new_password,
        client_ip(request, settings),
        request.headers.get("user-agent"),
    )
    response.set_cookie(
        settings.session_cookie_name,
        issued.session_token,
        max_age=settings.session_absolute_ttl_seconds,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    return TokenResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        expires_in=settings.access_token_ttl_seconds,
    )


@app.post("/api/v1/auth/verification/resend")
async def resend_verification(
    payload: VerificationResendRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> dict[str, str]:
    await enforce_limit(
        request,
        "verification-resend",
        [client_ip(request, settings) or "unknown"],
        settings.password_reset_rate_limit,
    )
    await service.resend_verification(db, str(payload.email))
    return {"message": "If verification is required, instructions have been sent."}


@app.post("/api/v1/setup", response_model=UserResponse, status_code=201)
async def setup(
    payload: SetupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> UserResponse:
    await enforce_limit(request, "setup", [client_ip(request, settings) or "unknown"], 5)
    user = await service.setup_admin(db, str(payload.email), payload.password, payload.instance_name)
    return UserResponse.model_validate(user)


@app.get("/api/v1/me", response_model=UserResponse)
async def me(
    session: Session = Depends(current_session), db: AsyncSession = Depends(get_db)
) -> UserResponse:
    user = (await db.execute(select(User).where(User.id == session.user_id))).scalar_one()
    return UserResponse.model_validate(user)


@app.get("/api/v1/me/sessions", response_model=list[SessionResponse])
async def my_sessions(
    current: Session = Depends(current_session), db: AsyncSession = Depends(get_db)
) -> list[SessionResponse]:
    sessions = (
        await db.execute(
            select(Session).where(Session.user_id == current.user_id).order_by(Session.created_at.desc())
        )
    ).scalars().all()
    return [
        SessionResponse.model_validate(item).model_copy(update={"current": item.id == current.id})
        for item in sessions
    ]


@app.delete("/api/v1/me/sessions/{session_id}", status_code=204)
async def revoke_device(
    session_id: str,
    current: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> None:
    target = (
        await db.execute(
            select(Session).where(Session.id == session_id, Session.user_id == current.user_id)
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Session not found")
    await service.revoke_session(db, target)


@app.post("/api/v1/auth/logout-all")
async def logout_all(
    current: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> dict[str, int]:
    count = await service.revoke_all_sessions(db, current.user_id)
    return {"revoked": count}


@app.get("/api/v1/applications", response_model=list[ApplicationResponse])
async def applications(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[ApplicationResponse]:
    rows = (await db.execute(select(Application).order_by(Application.created_at))).scalars().all()
    return [ApplicationResponse.model_validate(row) for row in rows]


@app.post("/api/v1/applications", response_model=ApplicationResponse, status_code=201)
async def create_application(
    payload: ApplicationCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> ApplicationResponse:
    item = Application(**payload.model_dump())
    db.add(item)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("APPLICATION_EXISTS", "Application slug is unavailable.", 409) from exc
    db.add(AuditEvent(actor_user_id=admin.user_id, action="application_created", target_type="application", target_id=item.id))
    await db.commit()
    return ApplicationResponse.model_validate(item)


@app.get("/api/v1/applications/{application_id}", response_model=ApplicationResponse)
async def application(
    application_id: str,
    _: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> ApplicationResponse:
    item = await db.get(Application, application_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return ApplicationResponse.model_validate(item)


@app.patch("/api/v1/applications/{application_id}", response_model=ApplicationResponse)
async def update_application(
    application_id: str,
    payload: ApplicationUpdate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> ApplicationResponse:
    item = await db.get(Application, application_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Application not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise AuthError("EMPTY_UPDATE", "At least one application field is required.", 422)
    for field, value in changes.items():
        setattr(item, field, value)
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="application_updated",
            target_type="application",
            target_id=item.id,
            metadata_json={"fields": sorted(changes)},
        )
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("APPLICATION_EXISTS", "Application slug is unavailable.", 409) from exc
    return ApplicationResponse.model_validate(item)


@app.delete("/api/v1/applications/{application_id}", status_code=204)
async def delete_application(
    application_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    item = await db.get(Application, application_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Application not found")
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="application_deleted",
            target_type="application",
            target_id=item.id,
            metadata_json={"slug": item.slug},
        )
    )
    await db.delete(item)
    await db.commit()


@app.get(
    "/api/v1/applications/{application_id}/environments",
    response_model=list[EnvironmentResponse],
)
async def environments(
    application_id: str,
    _: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> list[EnvironmentResponse]:
    rows = (
        await db.execute(
            select(ApplicationEnvironment).where(
                ApplicationEnvironment.application_id == application_id
            )
        )
    ).scalars().all()
    return [EnvironmentResponse.model_validate(row) for row in rows]


@app.post(
    "/api/v1/applications/{application_id}/environments",
    response_model=EnvironmentResponse,
    status_code=201,
)
async def create_environment(
    application_id: str,
    payload: EnvironmentCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> EnvironmentResponse:
    if (
        await db.execute(select(Application.id).where(Application.id == application_id))
    ).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Application not found")
    item = ApplicationEnvironment(
        application_id=application_id,
        name=payload.name,
        key=payload.key,
        issuer_url=validated_redirect_uri(payload.issuer_url),
        redirect_uris=[validated_redirect_uri(uri) for uri in payload.redirect_uris],
        allowed_origins=[validated_origin(origin) for origin in payload.allowed_origins],
    )
    db.add(item)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("ENVIRONMENT_EXISTS", "Environment key is unavailable.", 409) from exc
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="application_environment_created",
            target_type="application_environment",
            target_id=item.id,
            metadata_json={"application_id": application_id},
        )
    )
    await db.commit()
    return EnvironmentResponse.model_validate(item)


@app.patch(
    "/api/v1/applications/{application_id}/environments/{environment_id}",
    response_model=EnvironmentResponse,
)
async def update_environment(
    application_id: str,
    environment_id: str,
    payload: EnvironmentUpdate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> EnvironmentResponse:
    item = (
        await db.execute(
            select(ApplicationEnvironment).where(
                ApplicationEnvironment.id == environment_id,
                ApplicationEnvironment.application_id == application_id,
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Environment not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise AuthError("EMPTY_UPDATE", "At least one environment field is required.", 422)
    if "issuer_url" in changes:
        changes["issuer_url"] = validated_redirect_uri(cast(str, changes["issuer_url"]))
    if "redirect_uris" in changes:
        changes["redirect_uris"] = [
            validated_redirect_uri(uri) for uri in cast(list[str], changes["redirect_uris"])
        ]
    if "allowed_origins" in changes:
        changes["allowed_origins"] = [
            validated_origin(origin) for origin in cast(list[str], changes["allowed_origins"])
        ]
    for field, value in changes.items():
        setattr(item, field, value)
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="application_environment_updated",
            target_type="application_environment",
            target_id=item.id,
            metadata_json={"application_id": application_id, "fields": sorted(changes)},
        )
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("ENVIRONMENT_EXISTS", "Environment key is unavailable.", 409) from exc
    return EnvironmentResponse.model_validate(item)


@app.delete(
    "/api/v1/applications/{application_id}/environments/{environment_id}",
    status_code=204,
)
async def delete_environment(
    application_id: str,
    environment_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    item = (
        await db.execute(
            select(ApplicationEnvironment).where(
                ApplicationEnvironment.id == environment_id,
                ApplicationEnvironment.application_id == application_id,
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Environment not found")
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="application_environment_deleted",
            target_type="application_environment",
            target_id=item.id,
            metadata_json={"application_id": application_id, "key": item.key},
        )
    )
    await db.delete(item)
    await db.commit()


@app.get("/api/v1/users", response_model=list[UserResponse])
async def users(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[UserResponse]:
    rows = (await db.execute(select(User).order_by(User.created_at.desc()).limit(200))).scalars().all()
    return [UserResponse.model_validate(row) for row in rows]


@app.post("/api/v1/users/{user_id}/disable", response_model=UserResponse)
async def disable_user(
    user_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> UserResponse:
    if user_id == admin.user_id:
        raise AuthError("SELF_DISABLE_DENIED", "Administrators cannot disable themselves.", 409)
    user = await service.set_user_disabled(db, admin.user_id, user_id, True)
    return UserResponse.model_validate(user)


@app.post("/api/v1/users/{user_id}/enable", response_model=UserResponse)
async def enable_user(
    user_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> UserResponse:
    user = await service.set_user_disabled(db, admin.user_id, user_id, False)
    return UserResponse.model_validate(user)


@app.post("/api/v1/users/{user_id}/revoke-sessions")
async def admin_revoke_user_sessions(
    user_id: str,
    _: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> dict[str, int]:
    count = await service.revoke_all_sessions(db, user_id)
    return {"revoked": count}


ORG_PERMISSIONS = (
    "members:read", "members:invite", "members:remove", "members:write",
    "roles:read", "roles:write", "api_keys:read", "api_keys:write", "audit:read",
)


@app.post("/api/v1/organizations", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    payload: OrganizationCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> OrganizationResponse:
    organization = Organization(**payload.model_dump())
    db.add(organization)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("ORGANIZATION_EXISTS", "Organization slug is unavailable.", 409) from exc
    owner = Role(organization_id=organization.id, name="Owner", key="owner")
    admin_role = Role(organization_id=organization.id, name="Admin", key="admin")
    member = Role(organization_id=organization.id, name="Member", key="member")
    db.add_all([owner, admin_role, member])
    await db.flush()
    for key in ORG_PERMISSIONS:
        permission = (await db.execute(select(Permission).where(Permission.key == key))).scalar_one_or_none()
        if permission is None:
            permission = Permission(key=key)
            db.add(permission)
            await db.flush()
        db.add(RolePermission(role_id=owner.id, permission_id=permission.id))
        if key not in {"roles:write", "members:remove"}:
            db.add(RolePermission(role_id=admin_role.id, permission_id=permission.id))
        if key in {"members:read", "roles:read"}:
            db.add(RolePermission(role_id=member.id, permission_id=permission.id))
    db.add(Membership(organization_id=organization.id, user_id=admin.user_id, role_id=owner.id))
    db.add(AuditEvent(actor_user_id=admin.user_id, organization_id=organization.id, action="organization_created", target_type="organization", target_id=organization.id))
    await db.commit()
    return OrganizationResponse.model_validate(organization)


@app.get("/api/v1/organizations", response_model=list[OrganizationResponse])
async def organizations(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[OrganizationResponse]:
    rows = (await db.execute(select(Organization).order_by(Organization.created_at))).scalars().all()
    return [OrganizationResponse.model_validate(row) for row in rows]


@app.get("/api/v1/organizations/{organization_id}/members")
async def members(
    organization_id: str,
    actor: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, str]]:
    await authorization.require(db, actor.user_id, organization_id, "members:read")
    rows = (await db.execute(select(Membership).where(Membership.organization_id == organization_id))).scalars().all()
    return [{"id": row.id, "user_id": row.user_id, "role_id": row.role_id, "status": row.status} for row in rows]


@app.post(
    "/api/v1/organizations/{organization_id}/invitations",
    response_model=InvitationCreated,
    status_code=201,
)
async def create_invitation(
    organization_id: str,
    payload: InvitationCreate,
    actor: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> InvitationCreated:
    await authorization.require(db, actor.user_id, organization_id, "members:invite")
    invitation = await service.create_invitation(
        db, organization_id, actor.user_id, str(payload.email), payload.role_id
    )
    return InvitationCreated(
        id=invitation.id, email=invitation.email, expires_at=invitation.expires_at
    )


@app.post("/api/v1/invitations/accept", status_code=201)
async def accept_invitation(
    payload: InvitationAccept,
    actor: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> dict[str, str]:
    membership = await service.accept_invitation(db, actor.user_id, payload.token)
    return {"membership_id": membership.id, "organization_id": membership.organization_id}


@app.delete("/api/v1/organizations/{organization_id}/members/{membership_id}", status_code=204)
async def remove_member(
    organization_id: str,
    membership_id: str,
    actor: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> None:
    await authorization.require(db, actor.user_id, organization_id, "members:remove")
    target = (
        await db.execute(
            select(Membership)
            .where(
                Membership.id == membership_id,
                Membership.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    role = (await db.execute(select(Role).where(Role.id == target.role_id))).scalar_one()
    if role.key == "owner":
        owners = (
            await db.execute(
                select(Membership.id)
                .join(Role, Role.id == Membership.role_id)
                .where(
                    Membership.organization_id == organization_id,
                    Membership.status == "active",
                    Role.key == "owner",
                )
                .with_for_update()
            )
        ).scalars().all()
        if len(owners) <= 1:
            raise AuthError("LAST_OWNER", "The last owner cannot be removed.", 409)
    await db.delete(target)
    db.add(
        AuditEvent(
            actor_user_id=actor.user_id,
            organization_id=organization_id,
            action="membership_removed",
            target_type="membership",
            target_id=membership_id,
        )
    )
    await db.commit()


@app.patch("/api/v1/organizations/{organization_id}/members/{membership_id}/role")
async def change_member_role(
    organization_id: str,
    membership_id: str,
    payload: MembershipRoleUpdate,
    actor: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    await authorization.require(db, actor.user_id, organization_id, "roles:write")
    target = (await db.execute(select(Membership).where(Membership.id == membership_id, Membership.organization_id == organization_id).with_for_update())).scalar_one_or_none()
    new_role = (await db.execute(select(Role).where(Role.id == payload.role_id, Role.organization_id == organization_id))).scalar_one_or_none()
    if target is None or new_role is None:
        raise HTTPException(status_code=404, detail="Membership or role not found")
    old_role = (await db.execute(select(Role).where(Role.id == target.role_id))).scalar_one()
    if old_role.key == "owner" and new_role.key != "owner":
        owners = (await db.execute(select(Membership.id).join(Role, Role.id == Membership.role_id).where(Membership.organization_id == organization_id, Membership.status == "active", Role.key == "owner").with_for_update())).scalars().all()
        if len(owners) <= 1:
            raise AuthError("LAST_OWNER", "The last owner cannot be demoted.", 409)
    target.role_id = new_role.id
    db.add(AuditEvent(actor_user_id=actor.user_id, organization_id=organization_id, action="membership_role_changed", target_type="membership", target_id=target.id, metadata_json={"from_role_id": old_role.id, "to_role_id": new_role.id}))
    await db.commit()
    return {"id": target.id, "role_id": target.role_id}


@app.post("/api/v1/api-keys", response_model=ApiKeyCreated, status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreated:
    if (await db.execute(select(Application.id).where(Application.id == payload.application_id))).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Application not found")
    identifier = random_token("afid").split("_", 1)[1][:12]
    raw = f"af_live_{identifier}_{random_token('secret').split('_', 1)[1]}"
    prefix = f"af_live_{identifier}"
    item = ApiKey(application_id=payload.application_id, name=payload.name, prefix=prefix, key_hash=token_hash(raw), scopes=sorted(set(payload.scopes)), expires_at=payload.expires_at)
    db.add(item)
    await db.flush()
    db.add(AuditEvent(actor_user_id=admin.user_id, action="api_key_created", target_type="api_key", target_id=item.id, metadata_json={"scopes": item.scopes}))
    await db.commit()
    return ApiKeyCreated(id=item.id, secret=raw, prefix=prefix, scopes=item.scopes)


@app.get("/api/v1/api-keys", response_model=list[ApiKeyResponse])
async def api_keys(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[ApiKeyResponse]:
    rows = (await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))).scalars().all()
    return [ApiKeyResponse.model_validate(row) for row in rows]


@app.delete("/api/v1/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    item = (await db.execute(select(ApiKey).where(ApiKey.id == key_id).with_for_update())).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if item.revoked_at is not None:
        return
    item.revoked_at = datetime.now(UTC)
    db.add(AuditEvent(actor_user_id=admin.user_id, action="api_key_revoked", target_type="api_key", target_id=item.id))
    await db.commit()


@app.post("/api/v1/api-keys/{key_id}/rotate", response_model=ApiKeyCreated, status_code=201)
async def rotate_api_key(
    key_id: str,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreated:
    item = (
        await db.execute(select(ApiKey).where(ApiKey.id == key_id).with_for_update())
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if item.revoked_at is not None:
        raise AuthError("API_KEY_REVOKED", "A revoked API key cannot be rotated.", 409)

    identifier = random_token("afid").split("_", 1)[1][:12]
    raw = f"af_live_{identifier}_{random_token('secret').split('_', 1)[1]}"
    replacement = ApiKey(
        application_id=item.application_id,
        name=item.name,
        prefix=f"af_live_{identifier}",
        key_hash=token_hash(raw),
        scopes=item.scopes,
        expires_at=item.expires_at,
    )
    item.revoked_at = datetime.now(UTC)
    db.add(replacement)
    await db.flush()
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="api_key_rotated",
            target_type="api_key",
            target_id=item.id,
            metadata_json={"replacement_id": replacement.id},
        )
    )
    await db.commit()
    return ApiKeyCreated(
        id=replacement.id,
        secret=raw,
        prefix=replacement.prefix,
        scopes=replacement.scopes,
    )


@app.get("/api/v1/service/application", response_model=ApplicationResponse)
async def api_key_application(
    key: ApiKey = Depends(require_api_scope("applications:read")),
    db: AsyncSession = Depends(get_db),
) -> ApplicationResponse:
    # Application ID comes exclusively from the authenticated key, never request input.
    item = (await db.execute(select(Application).where(Application.id == key.application_id))).scalar_one()
    return ApplicationResponse.model_validate(item)


@app.post("/api/v1/machine-clients", response_model=MachineClientCreated, status_code=201)
async def create_machine_client(
    payload: MachineClientCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> MachineClientCreated:
    if (await db.execute(select(Application.id).where(Application.id == payload.application_id))).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Application not found")
    client_id = "af_client_" + uuid.uuid4().hex
    raw_secret = random_token("af_client_secret")
    item = MachineClient(application_id=payload.application_id, name=payload.name, client_id=client_id, client_secret_hash=token_hash(raw_secret), scopes=sorted(set(payload.scopes)))
    db.add(item)
    await db.flush()
    db.add(AuditEvent(actor_user_id=admin.user_id, action="machine_client_created", target_type="machine_client", target_id=item.id, metadata_json={"scopes": item.scopes}))
    await db.commit()
    return MachineClientCreated(id=item.id, client_id=client_id, client_secret=raw_secret, scopes=item.scopes)


@app.post("/api/v1/oauth/token", response_model=MachineTokenResponse)
async def client_credentials(
    payload: ClientCredentialsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> MachineTokenResponse:
    await enforce_limit(request, "oauth-token", [client_ip(request, settings) or "unknown", payload.client_id], 30)
    if payload.grant_type != "client_credentials":
        raise AuthError("UNSUPPORTED_GRANT_TYPE", "Grant type is unsupported.", 400)
    item = (await db.execute(select(MachineClient).where(MachineClient.client_id == payload.client_id))).scalar_one_or_none()
    if item is None or item.revoked_at is not None or not hmac.compare_digest(item.client_secret_hash, token_hash(payload.client_secret)):
        raise AuthError("INVALID_CLIENT", "Client authentication failed.", 401)
    access = service.jwt.issue(f"machine:{item.id}", f"machine:{item.id}", item.scopes)
    return MachineTokenResponse(access_token=access, expires_in=settings.access_token_ttl_seconds, scope=" ".join(item.scopes))


@app.post("/api/v1/oauth/clients", response_model=OAuthClientCreated, status_code=201)
async def create_oauth_client(
    payload: OAuthClientCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> OAuthClientCreated:
    if (await db.execute(select(Application.id).where(Application.id == payload.application_id))).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Application not found")
    redirects = [validated_redirect_uri(uri) for uri in payload.redirect_uris]
    if len(set(redirects)) != len(redirects):
        raise AuthError("INVALID_REDIRECT_URI", "Redirect URIs must be unique.", 400)
    client_id = "af_oidc_" + uuid.uuid4().hex
    raw_secret = None if payload.public else random_token("af_oidc_secret")
    item = OAuthClient(application_id=payload.application_id, client_id=client_id, client_secret_hash=token_hash(raw_secret) if raw_secret else None, redirect_uris=redirects, scopes=sorted(set(payload.scopes)), public=payload.public)
    db.add(item)
    await db.flush()
    db.add(AuditEvent(actor_user_id=admin.user_id, action="oauth_client_created", target_type="oauth_client", target_id=item.id))
    await db.commit()
    return OAuthClientCreated(id=item.id, client_id=client_id, client_secret=raw_secret, redirect_uris=redirects)


@app.post("/api/v1/oauth/authorize", response_model=AuthorizationResponse)
async def authorize(
    payload: AuthorizationRequest,
    request: Request,
    session: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> AuthorizationResponse:
    await enforce_limit(request, "oauth-authorize", [client_ip(request, settings) or "unknown", payload.client_id], 30)
    client = (await db.execute(select(OAuthClient).where(OAuthClient.client_id == payload.client_id))).scalar_one_or_none()
    if client is None or payload.redirect_uri not in client.redirect_uris:
        raise AuthError("INVALID_REDIRECT_URI", "Redirect URI is not registered.", 400)
    if payload.code_challenge_method != "S256":
        raise AuthError("INVALID_REQUEST", "PKCE S256 is required.", 400)
    requested_scopes = payload.scope.split()
    if "openid" not in requested_scopes or not set(requested_scopes).issubset(set(client.scopes)):
        raise AuthError("INVALID_SCOPE", "Requested scope is invalid.", 400)
    raw_code = random_token("af_code")
    db.add(AuthorizationCode(token_hash=token_hash(raw_code), client_id=client.client_id, user_id=session.user_id, session_id=session.id, redirect_uri=payload.redirect_uri, code_challenge=payload.code_challenge, scopes=requested_scopes, expires_at=datetime.now(UTC) + timedelta(minutes=5)))
    await db.commit()
    return AuthorizationResponse(code=raw_code, state=payload.state, redirect_uri=payload.redirect_uri)


@app.post("/api/v1/oauth/code-token", response_model=MachineTokenResponse)
async def authorization_code_token(
    payload: AuthorizationCodeTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    service: AuthService = Depends(auth_service),
) -> MachineTokenResponse:
    await enforce_limit(request, "oauth-token", [client_ip(request, settings) or "unknown", payload.client_id], 30)
    if payload.grant_type != "authorization_code":
        raise AuthError("UNSUPPORTED_GRANT_TYPE", "Grant type is unsupported.", 400)
    code = (await db.execute(select(AuthorizationCode).where(AuthorizationCode.token_hash == token_hash(payload.code)).with_for_update())).scalar_one_or_none()
    now = datetime.now(UTC)
    if code is None or code.used_at is not None or code.expires_at <= now:
        raise AuthError("INVALID_GRANT", "Authorization code is invalid.", 400)
    client = (await db.execute(select(OAuthClient).where(OAuthClient.client_id == payload.client_id))).scalar_one_or_none()
    if client is None or code.client_id != payload.client_id or code.redirect_uri != payload.redirect_uri:
        raise AuthError("INVALID_GRANT", "Authorization code binding is invalid.", 400)
    if not client.public and (not payload.client_secret or not hmac.compare_digest(client.client_secret_hash or "", token_hash(payload.client_secret))):
        raise AuthError("INVALID_CLIENT", "Client authentication failed.", 401)
    calculated = base64.urlsafe_b64encode(hashlib.sha256(payload.code_verifier.encode()).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(calculated, code.code_challenge):
        raise AuthError("INVALID_GRANT", "PKCE verification failed.", 400)
    active_session = (await db.execute(select(Session).where(Session.id == code.session_id).with_for_update())).scalar_one_or_none()
    if active_session is None or active_session.revoked_at is not None or active_session.expires_at <= now:
        raise AuthError("INVALID_GRANT", "Authorizing session is invalid.", 400)
    code.used_at = now
    access = service.jwt.issue(code.user_id, code.session_id, code.scopes)
    await db.commit()
    return MachineTokenResponse(access_token=access, expires_in=settings.access_token_ttl_seconds, scope=" ".join(code.scopes))


@app.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict[str, object]:
    issuer = settings.jwt_issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/api/v1/oauth/authorize",
        "token_endpoint": f"{issuer}/api/v1/oauth/code-token",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/api/v1/audit-events")
async def audit_events(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[dict[str, object]]:
    rows = (await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200))).scalars().all()
    return [{"id": row.id, "actor_user_id": row.actor_user_id, "organization_id": row.organization_id, "action": row.action, "target_type": row.target_type, "target_id": row.target_id, "metadata": row.metadata_json, "created_at": row.created_at} for row in rows]


@app.get("/api/v1/security-events")
async def security_events(
    _: Session = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[dict[str, object]]:
    rows = (await db.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(200))).scalars().all()
    return [{"id": row.id, "user_id": row.user_id, "event_type": row.event_type, "metadata": row.metadata_json, "created_at": row.created_at} for row in rows]


def validate_oauth_endpoint(value: str) -> str:
    parsed = urlparse(value)
    fixture = settings.authforge_env != "production" and parsed.hostname in {
        "oauth-fixture",
        "127.0.0.1",
        "localhost",
    }
    if not parsed.hostname or (parsed.scheme != "https" and not fixture):
        raise AuthError("INVALID_OAUTH_CONNECTION", "OAuth endpoints must use HTTPS.", 400)
    return value


@app.post("/api/v1/oauth/connections", status_code=201)
async def create_oauth_connection(
    payload: OAuthConnectionCreate,
    admin: Session = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    item = OAuthConnection(
        provider=payload.provider,
        issuer=validate_oauth_endpoint(payload.issuer),
        authorization_endpoint=validate_oauth_endpoint(payload.authorization_endpoint),
        token_endpoint=validate_oauth_endpoint(payload.token_endpoint),
        jwks_uri=validate_oauth_endpoint(payload.jwks_uri),
        client_id=payload.client_id,
        scopes=sorted(set(payload.scopes)),
    )
    db.add(item)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise AuthError("OAUTH_CONNECTION_EXISTS", "OAuth provider already exists.", 409) from exc
    db.add(
        AuditEvent(
            actor_user_id=admin.user_id,
            action="oauth_connection_created",
            target_type="oauth_connection",
            target_id=item.id,
        )
    )
    await db.commit()
    return {"id": item.id, "provider": item.provider, "enabled": item.enabled}


@app.post("/api/v1/oauth/connections/{provider}/link/start")
async def start_oauth_link(
    provider: str,
    payload: OAuthLinkStart,
    request: Request,
    session: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    await enforce_limit(
        request, "oauth-link", [client_ip(request, settings) or "unknown", provider], 20
    )
    connection = (
        await db.execute(
            select(OAuthConnection).where(
                OAuthConnection.provider == provider, OAuthConnection.enabled.is_(True)
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise HTTPException(status_code=404, detail="OAuth connection not found")
    expected_redirect = (
        f"{settings.oauth_callback_base_url.rstrip('/')}/api/v1/oauth/connections/"
        f"{provider}/callback"
    )
    if payload.redirect_uri != expected_redirect:
        raise AuthError("INVALID_REDIRECT_URI", "OAuth callback URI is invalid.", 400)
    raw_state = random_token("af_oauth_state")
    verifier = secrets.token_urlsafe(64)
    nonce = random_token("af_oidc_nonce")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    encrypted_verifier = Fernet(settings.authforge_encryption_key.encode()).encrypt(
        verifier.encode()
    ).decode()
    db.add(
        OAuthFlowState(
            state_hash=token_hash(raw_state),
            connection_id=connection.id,
            session_id=session.id,
            code_verifier_encrypted=encrypted_verifier,
            nonce_hash=token_hash(nonce),
            redirect_uri=expected_redirect,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    await db.commit()
    query = urlencode(
        {
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": expected_redirect,
            "scope": " ".join(connection.scopes),
            "state": raw_state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return {"authorization_url": f"{connection.authorization_endpoint}?{query}"}


@app.get("/api/v1/oauth/connections/{provider}/callback")
async def oauth_link_callback(
    provider: str,
    state: str,
    code: str,
    session: Session = Depends(current_session),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    now = datetime.now(UTC)
    flow = (
        await db.execute(
            select(OAuthFlowState)
            .join(OAuthConnection, OAuthConnection.id == OAuthFlowState.connection_id)
            .where(
                OAuthFlowState.state_hash == token_hash(state),
                OAuthConnection.provider == provider,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if flow is None or flow.used_at is not None or flow.expires_at <= now:
        raise AuthError("INVALID_OAUTH_STATE", "OAuth state is invalid or expired.", 400)
    if flow.session_id != session.id:
        raise AuthError("INVALID_OAUTH_STATE", "OAuth state is bound to another session.", 400)
    connection = (
        await db.execute(select(OAuthConnection).where(OAuthConnection.id == flow.connection_id))
    ).scalar_one()
    verifier = Fernet(settings.authforge_encryption_key.encode()).decrypt(
        flow.code_verifier_encrypted.encode()
    ).decode()
    async with httpx.AsyncClient(timeout=5.0) as client:
        token_response = await client.post(
            connection.token_endpoint,
            json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": connection.client_id,
                "redirect_uri": flow.redirect_uri,
                "code_verifier": verifier,
            },
        )
        if not token_response.is_success:
            raise AuthError("OAUTH_EXCHANGE_FAILED", "OAuth code exchange failed.", 400)
        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        if not isinstance(id_token, str):
            raise AuthError("OAUTH_ID_TOKEN_INVALID", "Provider ID token is missing.", 400)
        jwks_response = await client.get(connection.jwks_uri)
        jwks_response.raise_for_status()
    header = jwt.get_unverified_header(id_token)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise AuthError("OAUTH_ID_TOKEN_INVALID", "Provider signing semantics are invalid.", 400)
    jwks_data = jwks_response.json()
    jwk = next(
        (
            item
            for item in jwks_data.get("keys", [])
            if item.get("kid") == header["kid"] and item.get("alg") == "RS256"
        ),
        None,
    )
    if jwk is None:
        raise AuthError("OAUTH_ID_TOKEN_INVALID", "Provider signing key is unknown.", 400)
    try:
        claims = jwt.decode(
            id_token,
            jwt.PyJWK(jwk).key,
            algorithms=["RS256"],
            issuer=connection.issuer,
            audience=connection.client_id,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce"]},
        )
    except jwt.InvalidTokenError as exc:
        raise AuthError("OAUTH_ID_TOKEN_INVALID", "Provider ID token is invalid.", 400) from exc
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(flow.nonce_hash, token_hash(nonce)):
        raise AuthError("OAUTH_NONCE_INVALID", "Provider nonce is invalid.", 400)
    provider_user_id = str(claims["sub"])
    existing = (
        await db.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_user_id == provider_user_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None and existing.user_id != session.user_id:
        raise AuthError("OAUTH_ACCOUNT_IN_USE", "External account is already linked.", 409)
    if existing is None:
        db.add(
            OAuthAccount(
                provider=provider,
                provider_user_id=provider_user_id,
                user_id=session.user_id,
            )
        )
    flow.used_at = now
    flow.code_verifier_encrypted = "consumed"
    db.add(
        SecurityEvent(
            user_id=session.user_id,
            event_type="oauth_linked",
            metadata_json={"provider": provider},
        )
    )
    await db.commit()
    return {"provider": provider, "status": "linked"}
