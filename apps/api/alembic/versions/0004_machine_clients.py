"""Machine identities use dedicated client credentials."""
import sqlalchemy as sa
from alembic import op

revision = "0004_machine_clients"
down_revision = "0003_tenants_rbac_api_keys"


def upgrade() -> None:
    op.create_table(
        "machine_clients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("client_id", sa.String(80), nullable=False, unique=True),
        sa.Column("client_secret_hash", sa.String(64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_machine_clients_application_id", "machine_clients", ["application_id"])
    op.create_index("ix_machine_clients_client_id", "machine_clients", ["client_id"], unique=True)


def downgrade() -> None:
    op.drop_table("machine_clients")
