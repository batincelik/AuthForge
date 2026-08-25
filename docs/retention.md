# Data retention

PostgreSQL is the durable source of identity and security state. The worker performs bounded,
incremental cleanup; Redis loss never removes users, sessions, refresh families, permissions, or
credentials.

The following environment variables are measured in days:

- `TOKEN_RETENTION_DAYS` (default 7) retains expired or consumed verification, reset, OAuth-state,
  authorization-code, session, and refresh-family history after it is no longer live.
- `SECURITY_EVENT_RETENTION_DAYS` (default 90) controls security-event history.
- `AUDIT_EVENT_RETENTION_DAYS` (default 365) controls administrative audit history.
- `EMAIL_OUTBOX_RETENTION_DAYS` (default 30) applies only to delivered or permanently failed mail.
  Pending mail is never removed by retention cleanup.

`CLEANUP_BATCH_SIZE` defaults to 500 and is capped at 5,000 to prevent a cleanup cycle from issuing
an unbounded delete. Cleanup never deletes a live session or unexpired credential. Session deletion
is delayed past token retention and then cascades its refresh family, preserving reuse evidence
during the configured grace period.

IP addresses, user agents, and email destinations may be personal data. Operators should select
retention values that match their incident-response needs and applicable privacy obligations, and
include PostgreSQL backups and replicas in the same deletion policy.
