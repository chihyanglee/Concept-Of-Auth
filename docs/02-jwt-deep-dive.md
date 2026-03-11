# JWT Deep Dive

## Concept

A **JSON Web Token (JWT)** is a compact, self-contained way to transmit information between parties as a signed JSON object. The signature ensures the token hasn't been tampered with — the server can trust the claims inside without a database lookup.

JWTs solve the problem of stateless authentication: instead of storing session data server-side, the token itself carries the user's identity and permissions.

## How It Works

### Token Structure

A JWT has three parts separated by dots: `header.payload.signature`

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiJ9.abc123signature
│                      │                                                │
│  Header (base64)     │  Payload (base64)                              │  Signature
```

**Header** — metadata about the token:
```json
{
  "alg": "HS256",    // Signing algorithm
  "typ": "JWT"       // Token type
}
```

**Payload** — the claims (data):
```json
{
  "iss": "auth-server",     // Issuer: who created this token
  "sub": "1",               // Subject: who this token is about (user ID)
  "aud": "demo-client",     // Audience: who this token is intended for
  "exp": 1700000900,        // Expiration: unix timestamp when token expires
  "iat": 1700000000,        // Issued At: when the token was created
  "jti": "unique-id-here",  // JWT ID: unique identifier for this specific token
  "type": "access",         // Custom: token type
  "username": "admin",      // Custom: user's name
  "role": "admin",          // Custom: user's role
  "scopes": ["read","write"] // Custom: granted permissions
}
```

**Signature** — proves the token wasn't modified:
```
HMAC-SHA256(base64(header) + "." + base64(payload), secret_key)
```

Anyone can decode and read the header and payload (they're just base64). The signature is what prevents tampering — without the secret key, you can't create a valid signature.

### Signing Algorithms: HS256 vs RS256

| | HS256 (this project) | RS256 |
|---|---|---|
| **Type** | Symmetric (shared secret) | Asymmetric (public/private key pair) |
| **Sign with** | Secret key | Private key |
| **Verify with** | Same secret key | Public key |
| **Use case** | Single service (auth server is the only verifier) | Distributed systems (many services need to verify tokens) |
| **Trade-off** | Simpler, but every verifier needs the secret | More complex, but public key can be shared freely |

This project uses HS256 because there's only one server that both creates and verifies tokens. In a microservices architecture, RS256 would be better — you'd share the public key with all services, keeping the private key only on the auth server.

### Three Token Types

This project uses three distinct token types, each with a specific purpose:

**Access Token** (15 min expiry)
- Used to access protected resources
- Contains full user identity + permissions (role, scopes)
- Short-lived to limit damage if stolen
- Sent as `Authorization: Bearer <token>` header

**Refresh Token** (7 day expiry)
- Used only to get new access tokens
- Contains minimal claims (just user ID)
- Long-lived for user convenience (stay logged in)
- Never sent to resource endpoints — only to the auth server's refresh endpoint
- Should be stored more securely than access tokens

**ID Token** (1 hour expiry)
- OIDC-specific: proves the user's identity to the client application
- Contains user profile info (username, email)
- Not used for API access — it's for the client to know who the user is
- Includes a `nonce` for replay protection

**Why separate them?** If a single token did everything, stealing it would grant full access for its entire lifetime. Separation limits blast radius: a stolen access token expires in 15 minutes, and a stolen refresh token can't access resources directly.

### Token Revocation via JTI

Each token has a unique `jti` (JWT ID). When a token needs to be revoked (logout, security incident), the JTI is added to a blocklist in the database.

On every request, the server checks if the token's JTI is in the blocklist before granting access. This is checked inside `verify_token`.

**Cleanup:** Blocklist entries can be safely deleted after the token's natural `expires_at` — an expired token is rejected anyway, so there's no need to keep its JTI in the blocklist.

## In This Codebase

### Access token creation
- `jwt_utils.py:15-54` — `create_access_token()`:
  - Generates a unique JTI via `secrets.token_urlsafe(32)` (line 33)
  - Sets standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` (lines 36-44)
  - Adds custom claims: `username`, `role`, `scopes`, `client_id` (lines 47-52)
  - Signs with HS256 using `JWT_SECRET_KEY` (line 54)

### Refresh token creation
- `jwt_utils.py:56-83` — `create_refresh_token()`:
  - Intentionally minimal: no username, role, or scopes
  - Only carries `sub` (user ID) — permissions are fetched fresh when issuing a new access token
  - This means role changes take effect on next refresh, not next request

### ID token creation
- `jwt_utils.py:85-120` — `create_id_token()`:
  - Includes OIDC profile claims: `preferred_username`, `email`, `email_verified`
  - Includes `nonce` if provided (for replay protection)
  - 1-hour expiry (longer than access token because it's not used for API access)

### Token verification
- `jwt_utils.py:122-154` — `verify_token()`:
  - Decodes the JWT and verifies signature (line 135-139)
  - Checks blocklist via `TokenBlocklist.is_token_blocked(jti)` (line 142)
  - Validates token type matches expected type (line 146)
  - Returns `None` for any failure (expired, invalid signature, blocked, wrong type)

### Token revocation
- `jwt_utils.py:245-290` — `revoke_token()`:
  - Decodes with `verify_exp=False` (line 261) — must be able to revoke expired tokens too
  - Extracts JTI and creates a `TokenBlocklist` entry (lines 276-281)
  - The blocklist entry stores `expires_at` so it can be cleaned up later

### Configuration
- `app.py:13` — `JWT_SECRET_KEY`: the symmetric key used for HS256 signing
- `app.py:14` — access tokens expire in 15 minutes
- `app.py:15` — refresh tokens expire in 7 days

## Quiz

1. **A JWT has three parts. Which parts can anyone read without the secret key?** Which part requires the secret key to create?

2. **What happens if you change one character in a JWT's payload and send it to the server?** Walk through what `verify_token` does.

3. **Why does `create_refresh_token` not include `role` or `scopes`?** What would go wrong if it did and the user's role was changed by an admin?

4. **Why does `revoke_token` use `verify_exp=False` when decoding?** What scenario does this handle?

5. **If the `JWT_SECRET_KEY` is compromised, what can an attacker do?** What's the mitigation?

6. **What's the difference between a token being expired vs being revoked?** Can a token be both?

7. **Why is the JTI generated with `secrets.token_urlsafe(32)` instead of a simple incrementing counter?** What attack does this prevent?

8. **If you switched from HS256 to RS256, what changes in this codebase?** Which files would need modification?

## System Design Interview Questions

### 1. "Design a token management system for a microservices architecture with 50 services"

**What a strong answer covers:**
- RS256 over HS256: auth server signs with private key, services verify with public key
- JWKS (JSON Web Key Set) endpoint for key distribution and rotation
- Token introspection endpoint as a fallback for opaque tokens
- Short access token expiry (5-15 min) to minimize blocklist checks across services
- Centralized vs distributed blocklist (Redis pub/sub for propagation)
- Token scoping: each service only accepts tokens with specific audiences

### 2. "How would you handle token revocation at scale with millions of active users?"

**What a strong answer covers:**
- Blocklist size estimation: active_users × avg_tokens_per_user × revocation_rate
- Storage: Redis with TTL matching token expiry (auto-cleanup)
- Optimization: Bloom filter for fast "definitely not revoked" checks
- Trade-off: shorter token expiry reduces blocklist size but increases refresh traffic
- Emergency: global key rotation to invalidate ALL tokens instantly
- Monitoring: blocklist growth rate, cache hit ratio, cleanup lag

### 3. "Your access tokens contain user roles. A user's role is changed by an admin. How quickly does this take effect?"

**What a strong answer covers:**
- With current design: role change takes effect on next token refresh (up to 15 min delay)
- Option 1: Shorten access token expiry (more refresh traffic, but faster propagation)
- Option 2: Push-based revocation (revoke current access token when role changes, forcing a refresh)
- Option 3: Check role from DB on every request (defeats the purpose of JWT)
- The fundamental tension: self-contained tokens vs real-time consistency
- This project's approach: refresh token doesn't contain role, so new access tokens get the updated role
