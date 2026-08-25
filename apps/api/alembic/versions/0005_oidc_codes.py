"""OIDC clients and single-use PKCE-bound authorization codes."""
import sqlalchemy as sa
from alembic import op

revision = "0005_oidc_codes"
down_revision = "0004_machine_clients"


def upgrade() -> None:
    op.create_table("oauth_clients", sa.Column("id", sa.String(36), primary_key=True), sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False), sa.Column("client_id", sa.String(100), nullable=False, unique=True), sa.Column("client_secret_hash", sa.String(64)), sa.Column("redirect_uris", sa.JSON(), nullable=False), sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("public", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"], unique=True)
    op.create_index("ix_oauth_clients_application_id", "oauth_clients", ["application_id"])
    op.create_table("authorization_codes", sa.Column("id", sa.String(36), primary_key=True), sa.Column("token_hash", sa.String(64), nullable=False, unique=True), sa.Column("client_id", sa.String(100), nullable=False), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False), sa.Column("redirect_uri", sa.String(1000), nullable=False), sa.Column("code_challenge", sa.String(128), nullable=False), sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("used_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_authorization_codes_token_hash", "authorization_codes", ["token_hash"], unique=True)
    op.create_index("ix_authorization_codes_client_id", "authorization_codes", ["client_id"])


def downgrade() -> None:
    op.drop_table("authorization_codes")
    op.drop_table("oauth_clients")
