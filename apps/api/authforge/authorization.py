from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Membership, Permission, RolePermission
from .services import AuthError


class AuthorizationService:
    async def require(
        self, db: AsyncSession, actor_user_id: str, organization_id: str, permission: str
    ) -> Membership:
        membership = (
            await db.execute(
                select(Membership)
                .join(RolePermission, RolePermission.role_id == Membership.role_id)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(
                    Membership.user_id == actor_user_id,
                    Membership.organization_id == organization_id,
                    Membership.status == "active",
                    Permission.key == permission,
                )
            )
        ).scalar_one_or_none()
        if membership is None:
            raise AuthError("PERMISSION_DENIED", "Permission denied.", 403)
        return membership

