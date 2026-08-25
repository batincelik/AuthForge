import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import aiosmtplib
from authforge.database import SessionFactory
from authforge.models import (
    AuditEvent,
    AuthorizationCode,
    EmailOutbox,
    EmailVerificationToken,
    OAuthFlowState,
    PasswordResetToken,
    SecurityEvent,
    Session,
)
from cryptography.fernet import Fernet
from sqlalchemy import delete, or_, select


async def deliver(row: EmailOutbox) -> None:
    payload = json.loads(Fernet(os.environ["AUTHFORGE_ENCRYPTION_KEY"].encode()).decrypt(row.payload_encrypted.encode()))
    base = os.environ.get("DASHBOARD_URL", "http://localhost:3000")
    paths = {
        "verify_email": "verify-email",
        "password_reset": "reset-password",
        "organization_invitation": "accept-invitation",
    }
    path = paths.get(row.template)
    if path is None:
        raise ValueError("unknown email template")
    message = EmailMessage()
    message["From"] = os.environ.get("EMAIL_FROM", "no-reply@authforge.local")
    message["To"] = row.recipient
    subjects = {
        "verify_email": "Verify your email",
        "password_reset": "Reset your password",
        "organization_invitation": "You have been invited",
    }
    message["Subject"] = subjects[row.template]
    message.set_content(f"Open this one-time link: {base}/{path}?token={payload['token']}")
    await aiosmtplib.send(message, hostname=os.environ.get("SMTP_HOST", "mailpit"), port=int(os.environ.get("SMTP_PORT", "1025")))


async def tick() -> None:
    async with SessionFactory() as db:
        rows = (await db.execute(select(EmailOutbox).where(
            EmailOutbox.sent_at.is_(None), EmailOutbox.permanently_failed.is_(False),
            EmailOutbox.available_at <= datetime.now(UTC),
        ).order_by(EmailOutbox.created_at).limit(20).with_for_update(skip_locked=True))).scalars().all()
        for row in rows:
            try:
                await deliver(row)
                row.sent_at = datetime.now(UTC)
                row.payload_encrypted = "delivered"
            except Exception as exc:
                row.attempts += 1
                row.last_error = type(exc).__name__[:500]
                row.permanently_failed = row.attempts >= 5
                row.available_at = datetime.now(UTC) + timedelta(seconds=min(300, 2**row.attempts))
        await db.commit()


async def cleanup() -> None:
    now = datetime.now(UTC)
    token_cutoff = now - timedelta(days=int(os.environ.get("TOKEN_RETENTION_DAYS", "7")))
    security_cutoff = now - timedelta(
        days=int(os.environ.get("SECURITY_EVENT_RETENTION_DAYS", "90"))
    )
    audit_cutoff = now - timedelta(days=int(os.environ.get("AUDIT_EVENT_RETENTION_DAYS", "365")))
    outbox_cutoff = now - timedelta(days=int(os.environ.get("EMAIL_OUTBOX_RETENTION_DAYS", "30")))
    batch_size = min(5000, max(1, int(os.environ.get("CLEANUP_BATCH_SIZE", "500"))))
    async with SessionFactory() as db:
        await db.execute(
            delete(EmailVerificationToken).where(
                EmailVerificationToken.id.in_(
                    select(EmailVerificationToken.id)
                    .where(EmailVerificationToken.expires_at < token_cutoff)
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(PasswordResetToken).where(
                PasswordResetToken.id.in_(
                    select(PasswordResetToken.id)
                    .where(PasswordResetToken.expires_at < token_cutoff)
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(AuthorizationCode).where(
                AuthorizationCode.id.in_(
                    select(AuthorizationCode.id)
                    .where(AuthorizationCode.expires_at < token_cutoff)
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(OAuthFlowState).where(
                OAuthFlowState.id.in_(
                    select(OAuthFlowState.id)
                    .where(OAuthFlowState.expires_at < token_cutoff)
                    .limit(batch_size)
                )
            )
        )
        # Session deletion cascades its refresh family only after the retention grace period.
        await db.execute(
            delete(Session).where(
                Session.id.in_(
                    select(Session.id)
                    .where(
                        or_(
                            Session.expires_at < token_cutoff,
                            Session.revoked_at < token_cutoff,
                        )
                    )
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.id.in_(
                    select(SecurityEvent.id)
                    .where(SecurityEvent.created_at < security_cutoff)
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(AuditEvent).where(
                AuditEvent.id.in_(
                    select(AuditEvent.id)
                    .where(AuditEvent.created_at < audit_cutoff)
                    .limit(batch_size)
                )
            )
        )
        await db.execute(
            delete(EmailOutbox).where(
                EmailOutbox.id.in_(
                    select(EmailOutbox.id)
                    .where(
                        EmailOutbox.created_at < outbox_cutoff,
                        or_(
                            EmailOutbox.sent_at.is_not(None),
                            EmailOutbox.permanently_failed.is_(True),
                        ),
                    )
                    .limit(batch_size)
                )
            )
        )
        await db.commit()


async def main() -> None:
    cycles = 0
    while True:
        await tick()
        cycles += 1
        if cycles % 1800 == 0:
            await cleanup()
        await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
