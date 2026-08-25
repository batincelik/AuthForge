# Security policy

Do not report vulnerabilities in a public issue. Send a private report to the deployment operator or
repository security contact with the affected version, reproduction steps, impact, and any suggested
mitigation. Remove passwords, cookies, authorization headers, raw tokens, private keys, and personal
data from diagnostic material.

Operators should immediately revoke affected sessions, refresh families, API keys, or machine
clients as appropriate, preserve security and audit events, rotate compromised persistent keys, and
follow their incident-response policy. JWT signing-key rotation must retain old public keys until all
tokens signed by them have expired.

Only supported dependency versions and the current main branch receive fixes during initial project
development. Production users are responsible for HTTPS termination, persistent secret management,
database backups, monitoring, trusted-proxy configuration, and retention settings.
