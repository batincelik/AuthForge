# API keys

API keys contain an indexed identifier and 256-bit random secret. Only a SHA-256 digest and display prefix are retained. The full value is returned once. Authentication performs indexed prefix lookup, constant-time digest comparison, expiry and revocation checks, then deny-by-default scope evaluation. `last_used_at` writes are throttled.

