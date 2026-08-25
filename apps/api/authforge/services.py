import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import Settings
from .models import (
    AuditEvent,
    EmailOutbox,
    EmailVerificationToken,
    InstanceAdmin,
    Invitation,
    Membership,
    PasswordCredential,
    PasswordResetToken,
    RefreshToken,
    RefreshTokenFamily,
    Role,
    SecurityEvent,
    Session,
    User,
    UserStatus,
)
from .security import JWTService, PasswordService, normalize_email, random_token, token_hash


class AuthError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code, self.message, self.status_code = code, message, status_code


@dataclass
class IssuedTokens:
    session_token: str
    refresh_token: str
    access_token: str
    session: Session


class AuthService:
    def __init__(self, settings: Settings, passwords: PasswordService, jwt_service: JWTService) -> None:
        self.settings = settings
        self.passwords = passwords
        self.jwt = jwt_service

    async def register(self, db: AsyncSession, email: str, password: str, display_name: str | None) -> User:
        normalized = normalize_email(email)
        credential_hash = self.passwords.hash(password)
        raw_verification = random_token("af_verify")
        user = User(email=email.strip(), email_normalized=normalized, display_name=display_name)
        user.password = PasswordCredential(password_hash=credential_hash)
        db.add(user)
        try:
            await db.flush()
        except IntegrityError as exc:
            await db.rollback()
            raise AuthError("REGISTRATION_UNAVAILABLE", "Registration could not be completed.", 409) from exc
        db.add(EmailVerificationToken(
            user_id=user.id, token_hash=token_hash(raw_verification),
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        ))
        # The outbox payload is encrypted; the worker alone receives its persistent key.
        encrypted = Fernet(self.settings.authforge_encryption_key.encode()).encrypt(
            json.dumps({"token": raw_verification, "user_id": user.id}).encode()
        ).decode()
        db.add(EmailOutbox(template="verify_email", recipient=user.email, payload_encrypted=encrypted))
        db.add(SecurityEvent(user_id=user.id, event_type="user_registered"))
        await db.commit()
        return user

    async def setup_admin(
        self, db: AsyncSession, email: str, password: str, instance_name: str
    ) -> User:
        # A transaction-level advisory lock prevents two first-run requests both succeeding.
        await db.execute(text("SELECT pg_advisory_xact_lock(10472831)"))
        if (await db.execute(select(InstanceAdmin.id).limit(1))).first() is not None:
            raise AuthError("SETUP_COMPLETE", "Initial setup has already been completed.", 409)
        user = User(
            email=email.strip(),
            email_normalized=normalize_email(email),
            email_verified_at=datetime.now(UTC),
            display_name=instance_name,
            status=UserStatus.ACTIVE,
        )
        user.password = PasswordCredential(password_hash=self.passwords.hash(password))
        db.add(user)
        try:
            await db.flush()
        except IntegrityError as exc:
            await db.rollback()
            raise AuthError("SETUP_UNAVAILABLE", "Initial setup could not be completed.", 409) from exc
        db.add(InstanceAdmin(user_id=user.id))
        db.add(SecurityEvent(user_id=user.id, event_type="instance_admin_created"))
        await db.commit()
        return user

    async def login(self, db: AsyncSession, email: str, password: str, ip: str | None, ua: str | None) -> IssuedTokens:
        normalized = normalize_email(email)
        result = await db.execute(
            select(User).options(selectinload(User.password)).where(User.email_normalized == normalized)
        )
        user = result.scalar_one_or_none()
        if user is None:
            self.passwords.verify_dummy(password)
            db.add(SecurityEvent(event_type="login_failure", metadata_json={"reason": "invalid_credentials"}))
            await db.commit()
            raise AuthError("INVALID_CREDENTIALS", "Invalid email or password.", 401)
        now = datetime.now(UTC)
        if user.disabled_at or user.status == UserStatus.DISABLED:
            raise AuthError("ACCOUNT_DISABLED", "Account is unavailable.", 403)
        if user.locked_until and user.locked_until > now:
            raise AuthError("ACCOUNT_LOCKED", "Account is temporarily locked.", 423)
        valid, replacement = self.passwords.verify(user.password.password_hash, password)
        if not valid:
            user.failed_login_count += 1
            if user.failed_login_count >= 10:
                user.locked_until = now + timedelta(minutes=15)
                db.add(SecurityEvent(user_id=user.id, event_type="account_locked"))
            db.add(SecurityEvent(user_id=user.id, event_type="login_failure", metadata_json={"reason": "invalid_credentials"}))
            await db.commit()
            raise AuthError("INVALID_CREDENTIALS", "Invalid email or password.", 401)
        if replacement:
            user.password.password_hash = replacement
        if user.email_verified_at is None:
            db.add(SecurityEvent(user_id=user.id, event_type="login_failure", metadata_json={"reason": "email_not_verified"}))
            await db.commit()
            raise AuthError("EMAIL_NOT_VERIFIED", "Email verification is required.", 403)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        issued = await self._create_session(db, user, ip, ua)
        db.add(SecurityEvent(user_id=user.id, event_type="login_success"))
        await db.commit()
        return issued

    async def _create_session(self, db: AsyncSession, user: User, ip: str | None, ua: str | None) -> IssuedTokens:
        now = datetime.now(UTC)
        session_raw = random_token("af_session")
        refresh_raw = random_token("af_refresh")
        session = Session(
            user_id=user.id, token_hash=token_hash(session_raw), ip_address=ip,
            user_agent=(ua or "")[:512] or None,
            expires_at=now + timedelta(seconds=self.settings.session_absolute_ttl_seconds),
        )
        db.add(session)
        await db.flush()
        family = RefreshTokenFamily(session_id=session.id)
        db.add(family)
        await db.flush()
        db.add(RefreshToken(
            family_id=family.id, token_hash=token_hash(refresh_raw),
            expires_at=now + timedelta(seconds=self.settings.refresh_token_ttl_seconds),
        ))
        return IssuedTokens(session_raw, refresh_raw, self.jwt.issue(user.id, session.id), session)

    async def authenticate_session(self, db: AsyncSession, raw: str) -> Session:
        result = await db.execute(select(Session).where(Session.token_hash == token_hash(raw)))
        session = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if session is None or session.revoked_at or session.expires_at <= now:
            raise AuthError("SESSION_EXPIRED", "Session is invalid.", 401)
        if session.last_seen_at + timedelta(seconds=self.settings.session_idle_ttl_seconds) <= now:
            raise AuthError("SESSION_EXPIRED", "Session is invalid.", 401)
        if session.last_seen_at + timedelta(seconds=self.settings.session_last_seen_interval_seconds) <= now:
            session.last_seen_at = now
            await db.commit()
        return session

    async def refresh(self, db: AsyncSession, raw: str) -> tuple[str, str]:
        now = datetime.now(UTC)
        # PostgreSQL row locking serializes concurrent consumers of the same token.
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash(raw)).with_for_update()
        )
        old = result.scalar_one_or_none()
        if old is None:
            raise AuthError("REFRESH_TOKEN_INVALID", "Refresh token is invalid.", 401)
        family = (await db.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.id == old.family_id).with_for_update()
        )).scalar_one()
        session = (await db.execute(
            select(Session).where(Session.id == family.session_id).with_for_update()
        )).scalar_one()
        if old.consumed_at is not None:
            family.revoked_at = now
            session.revoked_at = now
            db.add(SecurityEvent(user_id=session.user_id, event_type="refresh_token_reuse", metadata_json={"family_id": family.id}))
            await db.commit()
            raise AuthError("REFRESH_TOKEN_REUSED", "Refresh token reuse detected; re-authentication required.", 401)
        if old.expires_at <= now or family.revoked_at or session.revoked_at or session.expires_at <= now:
            raise AuthError("REFRESH_TOKEN_INVALID", "Refresh token is invalid.", 401)
        new_raw = random_token("af_refresh")
        replacement = RefreshToken(
            family_id=family.id, parent_id=old.id, token_hash=token_hash(new_raw),
            expires_at=min(old.expires_at, now + timedelta(seconds=self.settings.refresh_token_ttl_seconds)),
        )
        db.add(replacement)
        await db.flush()
        old.consumed_at = now
        old.replaced_by_id = replacement.id
        await db.commit()
        return self.jwt.issue(session.user_id, session.id), new_raw

    async def revoke_session(self, db: AsyncSession, session: Session, event: str = "session_revoked") -> None:
        now = datetime.now(UTC)
        session.revoked_at = now
        await db.execute(update(RefreshTokenFamily).where(
            RefreshTokenFamily.session_id == session.id,
            RefreshTokenFamily.revoked_at.is_(None),
        ).values(revoked_at=now))
        db.add(SecurityEvent(user_id=session.user_id, event_type=event))
        await db.commit()

    async def revoke_all_sessions(
        self, db: AsyncSession, user_id: str, except_session_id: str | None = None
    ) -> int:
        now = datetime.now(UTC)
        condition = [Session.user_id == user_id, Session.revoked_at.is_(None)]
        if except_session_id:
            condition.append(Session.id != except_session_id)
        targets = list(
            (await db.execute(select(Session.id).where(*condition))).scalars().all()
        )
        await db.execute(update(Session).where(Session.id.in_(targets)).values(revoked_at=now))
        session_ids = select(Session.id).where(Session.user_id == user_id)
        if except_session_id:
            session_ids = session_ids.where(Session.id != except_session_id)
        await db.execute(
            update(RefreshTokenFamily)
            .where(
                RefreshTokenFamily.session_id.in_(session_ids),
                RefreshTokenFamily.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        db.add(SecurityEvent(user_id=user_id, event_type="all_sessions_revoked"))
        await db.commit()
        return len(targets)

    async def verify_email(self, db: AsyncSession, raw: str) -> None:
        now = datetime.now(UTC)
        token = (await db.execute(
            select(EmailVerificationToken)
            .where(EmailVerificationToken.token_hash == token_hash(raw)).with_for_update()
        )).scalar_one_or_none()
        if token is None or token.used_at is not None or token.expires_at <= now:
            raise AuthError("INVALID_VERIFICATION_TOKEN", "Verification token is invalid.", 400)
        user = (await db.execute(select(User).where(User.id == token.user_id).with_for_update())).scalar_one()
        token.used_at = now
        user.email_verified_at = now
        user.status = UserStatus.ACTIVE
        db.add(SecurityEvent(user_id=user.id, event_type="email_verified"))
        await db.commit()

    async def request_reset(self, db: AsyncSession, email: str) -> None:
        normalized = normalize_email(email)
        user = (await db.execute(select(User).where(User.email_normalized == normalized))).scalar_one_or_none()
        if user is not None:
            raw = random_token("af_reset")
            db.add(PasswordResetToken(
                user_id=user.id, token_hash=token_hash(raw),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ))
            encrypted = Fernet(self.settings.authforge_encryption_key.encode()).encrypt(
                json.dumps({"token": raw, "user_id": user.id}).encode()
            ).decode()
            db.add(EmailOutbox(template="password_reset", recipient=user.email, payload_encrypted=encrypted))
            db.add(SecurityEvent(user_id=user.id, event_type="password_reset_requested"))
        await db.commit()

    async def confirm_reset(self, db: AsyncSession, raw: str, new_password: str) -> None:
        new_hash = self.passwords.hash(new_password)
        now = datetime.now(UTC)
        token = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash(raw)).with_for_update()
        )).scalar_one_or_none()
        if token is None or token.used_at is not None or token.expires_at <= now:
            raise AuthError("INVALID_RESET_TOKEN", "Password reset token is invalid.", 400)
        credential = (await db.execute(
            select(PasswordCredential).where(PasswordCredential.user_id == token.user_id).with_for_update()
        )).scalar_one()
        token.used_at = now
        credential.password_hash = new_hash
        credential.changed_at = now
        session_ids = select(Session.id).where(Session.user_id == token.user_id)
        await db.execute(update(Session).where(Session.user_id == token.user_id, Session.revoked_at.is_(None)).values(revoked_at=now))
        await db.execute(update(RefreshTokenFamily).where(
            RefreshTokenFamily.session_id.in_(session_ids), RefreshTokenFamily.revoked_at.is_(None)
        ).values(revoked_at=now))
        db.add(SecurityEvent(user_id=token.user_id, event_type="password_reset_completed"))
        await db.commit()

    async def change_password(
        self,
        db: AsyncSession,
        current_session: Session,
        current_password: str,
        new_password: str,
        ip: str | None,
        ua: str | None,
    ) -> IssuedTokens:
        credential = (
            await db.execute(
                select(PasswordCredential)
                .where(PasswordCredential.user_id == current_session.user_id)
                .with_for_update()
            )
        ).scalar_one()
        valid, _ = self.passwords.verify(credential.password_hash, current_password)
        if not valid:
            raise AuthError("INVALID_CREDENTIALS", "Current password is invalid.", 401)
        new_hash = self.passwords.hash(new_password)
        now = datetime.now(UTC)
        credential.password_hash = new_hash
        credential.changed_at = now
        session_ids = select(Session.id).where(Session.user_id == current_session.user_id)
        await db.execute(
            update(Session)
            .where(Session.user_id == current_session.user_id, Session.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.execute(
            update(RefreshTokenFamily)
            .where(
                RefreshTokenFamily.session_id.in_(session_ids),
                RefreshTokenFamily.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        user = (await db.execute(select(User).where(User.id == current_session.user_id))).scalar_one()
        issued = await self._create_session(db, user, ip, ua)
        db.add(SecurityEvent(user_id=user.id, event_type="password_changed"))
        await db.commit()
        return issued

    async def resend_verification(self, db: AsyncSession, email: str) -> None:
        user = (
            await db.execute(select(User).where(User.email_normalized == normalize_email(email)))
        ).scalar_one_or_none()
        if user is not None and user.email_verified_at is None:
            now = datetime.now(UTC)
            await db.execute(
                update(EmailVerificationToken)
                .where(
                    EmailVerificationToken.user_id == user.id,
                    EmailVerificationToken.used_at.is_(None),
                )
                .values(used_at=now)
            )
            raw = random_token("af_verify")
            db.add(
                EmailVerificationToken(
                    user_id=user.id,
                    token_hash=token_hash(raw),
                    expires_at=now + timedelta(hours=24),
                )
            )
            encrypted = Fernet(self.settings.authforge_encryption_key.encode()).encrypt(
                json.dumps({"token": raw, "user_id": user.id}).encode()
            ).decode()
            db.add(
                EmailOutbox(
                    template="verify_email", recipient=user.email, payload_encrypted=encrypted
                )
            )
        await db.commit()

    async def create_invitation(
        self,
        db: AsyncSession,
        organization_id: str,
        actor_user_id: str,
        email: str,
        role_id: str,
    ) -> Invitation:
        role = (
            await db.execute(
                select(Role).where(Role.id == role_id, Role.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if role is None:
            raise AuthError("INVALID_ROLE", "Role does not belong to this organization.", 400)
        normalized = normalize_email(email)
        existing_user = (
            await db.execute(select(User.id).where(User.email_normalized == normalized))
        ).scalar_one_or_none()
        if existing_user is not None:
            existing_membership = (
                await db.execute(
                    select(Membership.id).where(
                        Membership.organization_id == organization_id,
                        Membership.user_id == existing_user,
                    )
                )
            ).scalar_one_or_none()
            if existing_membership is not None:
                raise AuthError("ALREADY_MEMBER", "User is already a member.", 409)
        raw = random_token("af_invite")
        invitation = Invitation(
            organization_id=organization_id,
            email=email.strip(),
            email_normalized=normalized,
            role_id=role.id,
            token_hash=token_hash(raw),
            expires_at=datetime.now(UTC) + timedelta(days=7),
            created_by_user_id=actor_user_id,
        )
        db.add(invitation)
        await db.flush()
        encrypted = Fernet(self.settings.authforge_encryption_key.encode()).encrypt(
            json.dumps({"token": raw, "invitation_id": invitation.id}).encode()
        ).decode()
        db.add(
            EmailOutbox(
                template="organization_invitation",
                recipient=invitation.email,
                payload_encrypted=encrypted,
            )
        )
        await db.commit()
        return invitation

    async def accept_invitation(
        self, db: AsyncSession, user_id: str, raw: str
    ) -> Membership:
        now = datetime.now(UTC)
        invitation = (
            await db.execute(
                select(Invitation)
                .where(Invitation.token_hash == token_hash(raw))
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            invitation is None
            or invitation.accepted_at is not None
            or invitation.expires_at <= now
        ):
            raise AuthError("INVALID_INVITATION", "Invitation is invalid.", 400)
        user = (
            await db.execute(select(User).where(User.id == user_id).with_for_update())
        ).scalar_one()
        if user.email_normalized != invitation.email_normalized or user.email_verified_at is None:
            raise AuthError(
                "INVITATION_EMAIL_MISMATCH",
                "Invitation requires the verified invited email address.",
                403,
            )
        membership = Membership(
            organization_id=invitation.organization_id,
            user_id=user.id,
            role_id=invitation.role_id,
            status="active",
        )
        db.add(membership)
        await db.flush()
        invitation.accepted_at = now
        db.add(
            AuditEvent(
                actor_user_id=user.id,
                organization_id=invitation.organization_id,
                action="invitation_accepted",
                target_type="membership",
                target_id=membership.id,
            )
        )
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            raise AuthError("INVITATION_ALREADY_ACCEPTED", "Invitation cannot be accepted.", 409) from exc
        return membership

    async def set_user_disabled(
        self, db: AsyncSession, actor_user_id: str, user_id: str, disabled: bool
    ) -> User:
        user = (
            await db.execute(select(User).where(User.id == user_id).with_for_update())
        ).scalar_one_or_none()
        if user is None:
            raise AuthError("USER_NOT_FOUND", "User not found.", 404)
        now = datetime.now(UTC)
        if disabled:
            user.status = UserStatus.DISABLED
            user.disabled_at = now
            session_ids = select(Session.id).where(Session.user_id == user.id)
            await db.execute(
                update(Session)
                .where(Session.user_id == user.id, Session.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            await db.execute(
                update(RefreshTokenFamily)
                .where(
                    RefreshTokenFamily.session_id.in_(session_ids),
                    RefreshTokenFamily.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            event_type, action = "user_disabled", "user_disabled"
        else:
            user.status = UserStatus.ACTIVE if user.email_verified_at else UserStatus.PENDING_VERIFICATION
            user.disabled_at = None
            event_type, action = "user_enabled", "user_enabled"
        db.add(SecurityEvent(user_id=user.id, event_type=event_type))
        db.add(
            AuditEvent(
                actor_user_id=actor_user_id,
                action=action,
                target_type="user",
                target_id=user.id,
            )
        )
        await db.commit()
        return user
