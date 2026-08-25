# Access tokens

Access tokens are ten-minute RS256 JWT authorization representations, not durable sessions. Validation fixes the allowed algorithm and checks `kid`, signature, issuer, audience, expiry, not-before, and required claims. Stateless tokens may remain usable until their short expiry after session revocation; refresh and cookie authentication stop immediately.

