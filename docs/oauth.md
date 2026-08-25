# External OAuth

Linking is available only to an authenticated user; AuthForge never links merely because provider email text matches. State is random, hashed, expiring, single-use, and bound to the initiating session and exact callback. PKCE uses S256. OIDC ID tokens use fixed RS256 verification with issuer, audience, expiry, `kid`, and nonce validation. Provider tokens are not retained.

