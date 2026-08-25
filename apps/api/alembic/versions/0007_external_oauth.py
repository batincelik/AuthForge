"""Durable external OAuth connections, single-use state, and identity accounts."""
import sqlalchemy as sa
from alembic import op

revision = "0007_external_oauth"
down_revision = "0006_invitations"


def upgrade() -> None:
    op.create_table("oauth_connections", sa.Column("id", sa.String(36), primary_key=True), sa.Column("provider", sa.String(80), nullable=False, unique=True), sa.Column("issuer", sa.String(500), nullable=False), sa.Column("authorization_endpoint", sa.String(500), nullable=False), sa.Column("token_endpoint", sa.String(500), nullable=False), sa.Column("jwks_uri", sa.String(500), nullable=False), sa.Column("client_id", sa.String(200), nullable=False), sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_oauth_connections_provider", "oauth_connections", ["provider"], unique=True)
    op.create_table("oauth_flow_states", sa.Column("id", sa.String(36), primary_key=True), sa.Column("state_hash", sa.String(64), nullable=False, unique=True), sa.Column("connection_id", sa.String(36), sa.ForeignKey("oauth_connections.id", ondelete="CASCADE"), nullable=False), sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False), sa.Column("code_verifier_encrypted", sa.Text(), nullable=False), sa.Column("nonce_hash", sa.String(64), nullable=False), sa.Column("redirect_uri", sa.String(1000), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_oauth_flow_states_state_hash", "oauth_flow_states", ["state_hash"], unique=True)
    op.create_index("ix_oauth_flow_states_connection_id", "oauth_flow_states", ["connection_id"])
    op.create_table("oauth_accounts", sa.Column("id", sa.String(36), primary_key=True), sa.Column("provider", sa.String(80), nullable=False), sa.Column("provider_user_id", sa.String(255), nullable=False), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("provider", "provider_user_id"))
    op.create_index("ix_oauth_accounts_user_id", "oauth_accounts", ["user_id"])


def downgrade() -> None:
    op.drop_table("oauth_accounts")
    op.drop_table("oauth_flow_states")
    op.drop_table("oauth_connections")
