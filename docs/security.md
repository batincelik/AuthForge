# Security architecture

Raw passwords and bearer credentials are excluded from logs and durable token columns. Human passwords use Argon2id; high-entropy random tokens use SHA-256 for deterministic indexed lookup. The distinction is intentional: an offline dictionary attack applies to passwords but is infeasible against a correctly generated 256-bit token.

Refresh tokens are family- and session-bound. A PostgreSQL row lock makes consumption atomic. A consumed token presented again is treated as theft: the family and session are revoked and `refresh_token_reuse` is recorded. Purpose-token consumption and password reset use row locks and a single transaction.

Browser sessions use HttpOnly, SameSite cookies and Secure in production. Stateful mutations authenticated by cookie reject absent or unapproved origins. Deploy only through HTTPS with an explicit trusted proxy configuration.

