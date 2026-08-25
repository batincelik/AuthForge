# Contributing to AuthForge

Security invariants come before feature breadth. Start by reading `masterprompt.txt`, keep durable
identity state in PostgreSQL, never persist or log raw credentials, and add a regression test for
every authentication or authorization change.

Before opening a change, run:

```sh
make lint
make test
npm run typecheck
npm test
npm run build
docker compose config --quiet
```

Changes to refresh rotation, token consumption, invitations, role changes, or session revocation
must use database transactions and include concurrent/replay tests where applicable. Tenant-owned
records must be queried with their application or organization boundary. Do not commit `.env`,
private signing keys, encryption keys, tokens, test traces, or production-derived fixtures.

Report suspected vulnerabilities privately using the process in `SECURITY.md`; do not open a public
issue containing exploit details or secrets.
