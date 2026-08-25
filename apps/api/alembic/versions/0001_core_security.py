"""Core users, credentials, sessions, tokens, events, and outbox."""
import sqlalchemy as sa
from alembic import op

revision = "0001_core_security"
down_revision = None


def upgrade() -> None:
    status = sa.Enum("ACTIVE", "DISABLED", "LOCKED", "PENDING_VERIFICATION", name="userstatus")
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("email", sa.String(320), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=False), sa.Column("email_verified_at", sa.DateTime(timezone=True)),
        sa.Column("display_name", sa.String(200)), sa.Column("status", status, nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False), sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("email_normalized"))
    op.create_index("ix_users_email_normalized", "users", ["email_normalized"], unique=True)
    op.create_table("password_credentials", sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True), sa.Column("password_hash", sa.Text(), nullable=False), sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("sessions", sa.Column("id", sa.String(36), primary_key=True), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False, unique=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("ip_address", sa.String(45)), sa.Column("user_agent", sa.String(512)), sa.Column("device_name", sa.String(120)))
    for name, cols in [("ix_sessions_token_hash", ["token_hash"]), ("ix_sessions_expires_at", ["expires_at"]), ("ix_sessions_user_revoked", ["user_id", "revoked_at"])]:
        op.create_index(name, "sessions", cols)
    op.create_table("refresh_token_families", sa.Column("id", sa.String(36), primary_key=True), sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.create_index("ix_refresh_token_families_session_id", "refresh_token_families", ["session_id"])
    op.create_table("refresh_tokens", sa.Column("id", sa.String(36), primary_key=True), sa.Column("family_id", sa.String(36), sa.ForeignKey("refresh_token_families.id", ondelete="CASCADE"), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False, unique=True), sa.Column("parent_id", sa.String(36), sa.ForeignKey("refresh_tokens.id")), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("consumed_at", sa.DateTime(timezone=True)), sa.Column("replaced_by_id", sa.String(36)))
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])
    for table in ("email_verification_tokens", "password_reset_tokens"):
        op.create_table(table, sa.Column("id", sa.String(36), primary_key=True), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False, unique=True), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
        op.create_index(f"ix_{table}_token_hash", table, ["token_hash"], unique=True)
    op.create_table("security_events", sa.Column("id", sa.String(36), primary_key=True), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")), sa.Column("event_type", sa.String(80), nullable=False), sa.Column("metadata_json", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_table("email_outbox", sa.Column("id", sa.String(36), primary_key=True), sa.Column("template", sa.String(80), nullable=False), sa.Column("recipient", sa.String(320), nullable=False), sa.Column("payload_encrypted", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("available_at", sa.DateTime(timezone=True), nullable=False), sa.Column("sent_at", sa.DateTime(timezone=True)), sa.Column("attempts", sa.Integer(), nullable=False), sa.Column("last_error", sa.String(500)), sa.Column("permanently_failed", sa.Boolean(), nullable=False))


def downgrade() -> None:
    for table in ("email_outbox", "security_events", "password_reset_tokens", "email_verification_tokens", "refresh_tokens", "refresh_token_families", "sessions", "password_credentials", "users"):
        op.drop_table(table)
    sa.Enum(name="userstatus").drop(op.get_bind(), checkfirst=True)
