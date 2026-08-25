# RBAC

Authorization is centralized in `AuthorizationService.require(actor, organization, permission)`. Queries join the actor's active membership, organization-local role, role permissions, and exact requested permission. Missing permission denies access. Every resource query includes the organization identifier. Backend transactions prevent removal or demotion of the final active owner.

