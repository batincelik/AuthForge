# Refresh-token lifecycle

Refresh tokens are 256-bit random bearer credentials stored only as SHA-256 digests. Each belongs to a durable family and server-side session. Rotation locks the token, family, and session rows in PostgreSQL, consumes the presented token, and creates one successor. A consumed token presented again revokes the family and session and records `refresh_token_reuse`. Consequently, a concurrent loser also triggers the theft response and invalidates the single winner's successor.

