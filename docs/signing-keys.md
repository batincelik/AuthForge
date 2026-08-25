# Signing keys

The active RSA private key lives in a persistent secret volume. Rotation archives the prior public key, atomically replaces active material, records persistent active-key metadata, and publishes both keys. Old public keys remain until operators verify every token they signed has expired. Private material is never exposed through JWKS or management APIs.

