"""Applications, organizations, centralized RBAC, API keys, and audit events."""
import sqlalchemy as sa
from alembic import op

revision = "0003_tenants_rbac_api_keys"
down_revision = "0002_instance_admins"


def id_col() -> sa.Column[str]:
    return sa.Column("id", sa.String(36), primary_key=True)


def upgrade() -> None:
    op.create_table("applications", id_col(), sa.Column("name", sa.String(120), nullable=False), sa.Column("slug", sa.String(120), nullable=False, unique=True), sa.Column("description", sa.String(500)), sa.Column("application_type", sa.String(20), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_applications_slug", "applications", ["slug"], unique=True)
    op.create_table("application_environments", id_col(), sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(80), nullable=False), sa.Column("key", sa.String(80), nullable=False), sa.Column("issuer_url", sa.String(500), nullable=False), sa.Column("redirect_uris", sa.JSON(), nullable=False), sa.Column("allowed_origins", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("application_id", "key"))
    op.create_index("ix_application_environments_application_id", "application_environments", ["application_id"])
    op.create_table("organizations", id_col(), sa.Column("name", sa.String(120), nullable=False), sa.Column("slug", sa.String(120), nullable=False, unique=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
    op.create_table("roles", id_col(), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(80), nullable=False), sa.Column("key", sa.String(80), nullable=False), sa.Column("description", sa.String(300)), sa.UniqueConstraint("organization_id", "key"))
    op.create_index("ix_roles_organization_id", "roles", ["organization_id"])
    op.create_table("permissions", id_col(), sa.Column("key", sa.String(100), nullable=False, unique=True), sa.Column("description", sa.String(300)))
    op.create_index("ix_permissions_key", "permissions", ["key"], unique=True)
    op.create_table("role_permissions", sa.Column("role_id", sa.String(36), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True), sa.Column("permission_id", sa.String(36), sa.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True))
    op.create_table("memberships", id_col(), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("role_id", sa.String(36), sa.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False), sa.Column("status", sa.String(20), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "user_id"))
    op.create_index("ix_memberships_organization_id", "memberships", ["organization_id"])
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_table("api_keys", id_col(), sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(120), nullable=False), sa.Column("prefix", sa.String(32), nullable=False, unique=True), sa.Column("key_hash", sa.String(64), nullable=False, unique=True), sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True)), sa.Column("last_used_at", sa.DateTime(timezone=True)), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"], unique=True)
    op.create_index("ix_api_keys_application_id", "api_keys", ["application_id"])
    op.create_table("audit_events", id_col(), sa.Column("actor_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="SET NULL")), sa.Column("action", sa.String(100), nullable=False), sa.Column("target_type", sa.String(80), nullable=False), sa.Column("target_id", sa.String(80), nullable=False), sa.Column("metadata_json", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_audit_events_action", "audit_events", ["action"])


def downgrade() -> None:
    for table in ("audit_events", "api_keys", "memberships", "role_permissions", "permissions", "roles", "organizations", "application_environments", "applications"):
        op.drop_table(table)
