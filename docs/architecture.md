# Architecture

```mermaid
flowchart TD
  Apps[Applications and SDKs] --> API[AuthForge API]
  Dashboard[Administrator dashboard] --> API
  API --> PG[(PostgreSQL durable identity state)]
  API --> Redis[(Redis rate limits and temporary coordination)]
  API --> Outbox[Transactional email outbox]
  Outbox --> Worker[Email worker]
  Worker --> SMTP[SMTP / Mailpit]
  API --> JWT[Short-lived RS256 access tokens]
  JWT --> JWKS[Public JWKS]
```

PostgreSQL is authoritative for credentials, sessions, refresh families, tenants, RBAC, API keys, OAuth clients, authorization codes, and security/audit events. Redis loss can reset abuse counters but cannot create an authenticated identity or revive a revoked credential.

