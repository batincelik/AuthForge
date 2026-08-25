# Reverse proxy

Set exact `TRUSTED_PROXY_CIDRS`; forwarded addresses are ignored unless the direct peer belongs to one of those networks. Terminate HTTPS at the trusted proxy, forward the original scheme and host, preserve the stable issuer, and never expose the API over plaintext in production. Production startup requires HTTPS and a `__Host-` cookie name.

