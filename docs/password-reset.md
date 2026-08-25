# Password reset

Reset requests always return the same public response. Existing users receive an encrypted-outbox email containing a random token whose database representation is only a digest. Confirmation locks the reset row, replaces the Argon2id credential, consumes the token, revokes every session and refresh family, and records a security event in one transaction.

