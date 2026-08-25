# OIDC provider

AuthForge publishes discovery and JWKS and implements authorization code with mandatory PKCE S256. Codes are random, hashed, five-minute, single-use, session-, client-, redirect-, and challenge-bound. Row locking prevents concurrent exchanges. Implicit flow is unsupported.

