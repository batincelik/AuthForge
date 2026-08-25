# Sessions

Sessions are authoritative PostgreSQL rows addressed by a SHA-256 digest of a 256-bit random bearer token. Authentication rejects revoked, absolute-expired, and idle-expired rows. `last_seen_at` is updated at a bounded interval. Logout and device revocation update server state and revoke associated refresh families. Password changes and resets revoke all existing sessions; password change creates a fresh rotated session.

