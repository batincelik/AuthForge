# AuthForge

Self-hosted authentication and identity infrastructure with Argon2id credentials, PostgreSQL-backed sessions, encrypted transactional email delivery, reset and verification, rotating RS256 keys/JWKS, single-use refresh rotation, organizations/RBAC, scoped API keys, machine clients, and PKCE-secured OAuth/OIDC flows.

## Quick start

```bash
cp .env.example .env
# Replace AUTHFORGE_ENCRYPTION_KEY with a persistent Fernet key.
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
docker compose up --build
```

API: `http://localhost:8000`; dashboard: `http://localhost:3000`; Mailpit: `http://localhost:8025`.

Signing keys are generated once into the persistent `signing_keys` volume. Production operators must provision and back up their own keys, use HTTPS, rotate keys with an overlap at least as long as the maximum access-token lifetime, and never commit secrets.

## Security model

PostgreSQL is authoritative. Passwords use configurable Argon2id and transparent rehashing. Random bearer credentials are SHA-256 hashed for indexed lookup; unlike human passwords, 256-bit random tokens do not benefit from slow password hashing. Session, refresh, verification, and reset tokens are never stored raw. Email delivery capability is encrypted in the outbox and destroyed after successful delivery. Refresh rotation locks the token/family/session rows; reuse revokes the entire family and session.

Access JWTs are short-lived RS256 representations, not sessions. Session and refresh revocation is immediate; already issued stateless access tokens remain valid until their short expiry. Cookie-authenticated mutations require an allowed Origin. Credentialed CORS uses explicit origins.

## Features

AuthForge includes separate administrator and application-user privilege domains, device sessions, refresh-family theft response, Mailpit-backed verification/reset, exact application redirect/origin environments, organization invitations, centralized RBAC and owner protection, one-time API and machine secrets, authorization code plus PKCE, explicit external identity linking, Python and TypeScript SDKs, and a real-data security dashboard.

## Limitations

MFA/passkeys are roadmap items. Access JWT revocation is bounded by their short lifetime rather than a per-request blacklist. The built-in administrator UI intentionally covers core users, sessions, applications, keys, and events before advanced customization. Production deployment still requires an operator security review, durable secret management, HTTPS, backups, monitoring, and retention choices appropriate to the installation.
