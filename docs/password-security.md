# Password security

Passwords are bounded before hashing and processed with configurable Argon2id through `argon2-cffi`. Successful verification transparently rehashes credentials when parameters change. Unknown-account login executes a dummy Argon2 verification. PostgreSQL uniquely constrains conservative normalized email addresses. Passwords are never emitted to logs, events, or outbox payloads.

