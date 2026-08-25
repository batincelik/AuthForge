# Organizations

Organizations contain memberships referencing organization-local roles. Invitations bind a hashed, expiring token to an exact conservatively normalized email and role. Acceptance requires an authenticated user with that verified address, locks the token, and relies on a database membership uniqueness constraint.

