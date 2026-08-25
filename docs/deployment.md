# Production deployment

Terminate TLS at a trusted reverse proxy and set `AUTHFORGE_ENV=production`, an HTTPS issuer, explicit CORS origins, a `__Host-` session cookie name, and exact trusted proxy CIDRs. Provision persistent RSA and Fernet keys through a secret manager; never generate or replace them during routine restarts. Back up PostgreSQL and signing/encryption keys independently. Retain old public signing keys until every token they signed has expired.

