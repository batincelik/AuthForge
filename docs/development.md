# Development

Copy `.env.example`, generate a persistent Fernet key, then run `docker compose up --build`. PostgreSQL is authoritative, Redis provides abuse counters, and Mailpit is available at port 8025. Use `docker compose --profile test up` for the deterministic OIDC fixture. Run `make migrate`, `make test-security`, `make lint`, and `npm run build` before committing.

