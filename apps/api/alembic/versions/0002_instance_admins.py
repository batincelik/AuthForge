"""Separate instance administrators from application users."""
import sqlalchemy as sa
from alembic import op

revision = "0002_instance_admins"
down_revision = "0001_core_security"


def upgrade() -> None:
    op.create_table(
        "instance_admins",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_instance_admins_user_id", "instance_admins", ["user_id"], unique=True)


def downgrade() -> None:
    op.drop_table("instance_admins")
