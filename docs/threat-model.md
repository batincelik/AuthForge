# Threat model

AuthForge currently mitigates database password disclosure with Argon2id, bearer-token database disclosure with hashing, session theft with expiry/revocation, refresh theft with rotation and reuse detection, duplicate registration with a database uniqueness constraint, reset/verification replay with transactional single-use state, JWT forgery/confusion with fixed RS256 validation and `kid`, and CSRF/CORS abuse with explicit origins.

Residual risks include XSS in integrating applications, an attacker using a stolen access JWT until its short expiration, distributed abuse across many IP/account identities, endpoint timing variance beyond password verification, compromised application hosts, malicious instance administrators configuring provider endpoints, and operational key loss. Rate limiting, OAuth linking, RBAC, and API keys are enforced controls but do not replace deployment monitoring and review.
