# OAuth 2.0 Flows

## Concept

**The problem OAuth solves:** You want a third-party app to access your data (e.g., a calendar app reading your Google contacts), but you don't want to give that app your Google password.

**OAuth 2.0** is a delegation framework. Instead of sharing credentials, the user grants the third-party app a limited, revocable token that can only do specific things (scopes). The user's password never leaves the auth server.

**Key roles in OAuth:**
- **Resource Owner** — the user who owns the data
- **Client** — the third-party application requesting access
- **Authorization Server** — issues tokens after user consent (this project)
- **Resource Server** — hosts the protected data (not implemented here)

## How It Works

### Authorization Code Flow

This is the most common and most secure OAuth flow. It's used when a web or mobile app needs to act on behalf of a user.

```
┌──────┐     ┌──────────┐     ┌────────────┐     ┌──────────┐
│ User │     │  Client  │     │ Auth Server│     │ Resource │
│      │     │  (App)   │     │ (this proj)│     │  Server  │
└──┬───┘     └────┬─────┘     └─────┬──────┘     └────┬─────┘
   │              │                  │                  │
   │  1. Click    │                  │                  │
   │  "Login"     │                  │                  │
   │─────────────>│                  │                  │
   │              │                  │                  │
   │              │ 2. Redirect to   │                  │
   │              │ /oauth/authorize │                  │
   │              │ (with client_id, │                  │
   │              │  redirect_uri,   │                  │
   │              │  scope, state,   │                  │
   │              │  code_challenge) │                  │
   │<─────────────│─────────────────>│                  │
   │              │                  │                  │
   │  3. User sees consent page      │                  │
   │     "App X wants to read/write" │                  │
   │  4. User clicks "Authorize"     │                  │
   │────────────────────────────────>│                  │
   │              │                  │                  │
   │              │ 5. Redirect to   │                  │
   │              │ redirect_uri     │                  │
   │              │ with ?code=xxx   │                  │
   │              │ &state=yyy       │                  │
   │<─────────────│<─────────────────│                  │
   │              │                  │                  │
   │              │ 6. POST /oauth/token               │
   │              │ (code, client_secret,              │
   │              │  code_verifier)  │                  │
   │              │─────────────────>│                  │
   │              │                  │                  │
   │              │ 7. Return        │                  │
   │              │ access_token +   │                  │
   │              │ refresh_token    │                  │
   │              │<─────────────────│                  │
   │              │                  │                  │
   │              │ 8. Use access_token to call API     │
   │              │─────────────────────────────────────>│
   │              │                  │                  │
   │              │ 9. Return protected data            │
   │              │<─────────────────────────────────────│
```

**Why not just return the token directly in step 5?** The redirect URL is visible in the browser's address bar and history. The authorization code is a one-time-use, short-lived intermediary. The actual token exchange happens server-to-server (step 6), where the client authenticates with its secret.

### PKCE (Proof Key for Code Exchange)

**The problem PKCE solves:** In mobile apps and SPAs, the client can't securely store a `client_secret`. An attacker who intercepts the authorization code could exchange it for tokens.

**How it works:**

```
1. Client generates a random string: code_verifier
2. Client hashes it: code_challenge = BASE64URL(SHA256(code_verifier))
3. Client sends code_challenge in step 2 (authorize request)
4. Auth server stores code_challenge with the authorization code
5. Client sends code_verifier in step 6 (token exchange)
6. Auth server hashes the verifier and compares with stored challenge
```

Even if an attacker intercepts the authorization code, they don't have the `code_verifier`, so they can't complete the token exchange.

**S256 vs plain:**
- `S256`: code_challenge = SHA256(code_verifier) — recommended, the verifier is never exposed
- `plain`: code_challenge = code_verifier — only for environments that can't do SHA256

### Client Credentials Flow

Used for **machine-to-machine** communication where no user is involved (e.g., a backend service calling another backend service).

```
┌──────────┐     ┌────────────┐
│  Client  │     │ Auth Server│
│ (Service)│     │            │
└────┬─────┘     └─────┬──────┘
     │                  │
     │ POST /oauth/token│
     │ grant_type=      │
     │ client_credentials│
     │ client_id=xxx    │
     │ client_secret=xxx│
     │ scope=read       │
     │─────────────────>│
     │                  │
     │ access_token     │
     │ (no refresh      │
     │  token — client  │
     │  can always      │
     │  re-authenticate)│
     │<─────────────────│
```

No refresh token is issued — the client can simply re-authenticate with its credentials whenever the access token expires.

### Security Parameters

**state** — A random value the client generates and includes in the authorize request. The auth server returns it unchanged in the redirect. The client verifies it matches. This prevents **CSRF attacks**: an attacker can't trick your browser into completing an OAuth flow they initiated.

**redirect_uri** — Must exactly match one of the URIs registered for the client. This prevents an attacker from registering a malicious redirect URI to steal authorization codes.

**scope** — Limits what the token can do. The client requests scopes, the user can see what they're granting, and the auth server only issues tokens with allowed scopes.

## In This Codebase

### OAuth client registration
- `models.py:75-134` — Client model:
  - `client_secret` is hashed with `generate_password_hash` (line 109) — treated like a password
  - `redirect_uris` stored as comma-separated string, validated via `is_valid_redirect_uri` (line 131)
  - `scopes` stored as space-separated string, parsed by `get_scopes` (line 128)
- `app.py:55-63` — demo client seeded on first run with `redirect_uris='http://localhost:3000/callback'`

### Authorization endpoint
- `oauth_routes.py:89-272` — `/oauth/authorize`:
  - GET (lines 123-207): validates parameters, checks client exists, validates redirect URI, filters scopes against client's allowed scopes, renders HTML consent page
  - POST (lines 209-272): if user approves, creates `AuthorizationCode` and redirects with `?code=xxx&state=yyy`
  - If user denies, redirects with `?error=access_denied`

### Authorization code model
- `models.py:135-216` — AuthorizationCode:
  - `code` generated via `secrets.token_urlsafe(32)` (line 169) — cryptographically random
  - `expires_at` set to 10 minutes from creation (line 176)
  - `used` flag prevents replay — code can only be exchanged once (line 153)
  - `code_challenge` and `code_challenge_method` store PKCE data (lines 150-151)

### PKCE verification
- `models.py:186-211` — `verify_pkce()`:
  - S256 (lines 202-207): hashes code_verifier with SHA256, base64url encodes, strips padding, compares
  - Plain (lines 208-209): direct string comparison
  - If no code_challenge was stored, PKCE is not required (line 199-200)

### Token exchange
- `oauth_routes.py:350-441` — `handle_authorization_code_exchange()`:
  - Validates client credentials (line 367)
  - Finds and validates authorization code (lines 374-379)
  - Checks redirect URI matches (line 382)
  - Validates PKCE if used (line 389)
  - Marks code as used (line 404) — prevents replay
  - Issues access + refresh tokens (lines 410-421)
  - Issues ID token if `openid` scope was granted (lines 432-437)

### Client credentials flow
- `oauth_routes.py:495-536` — `handle_client_credentials_flow()`:
  - Validates client with client_id + client_secret
  - Filters requested scopes against allowed scopes
  - Issues access token with `user_id=None` and `role='client'` (line 523-528)
  - No refresh token — the client can re-authenticate anytime

## Quiz

1. **Why does the authorization code flow have two steps (get code, then exchange for token) instead of returning the token directly in the redirect?** What attack does this prevent?

2. **What would happen if `AuthorizationCode.used` wasn't checked?** Describe the attack.

3. **In PKCE S256, the client sends the `code_challenge` first, then the `code_verifier` later. Why this order?** What if it were reversed?

4. **Why is the authorization code set to expire in 10 minutes?** What would happen with a longer expiry?

5. **Why does the client credentials flow not return a refresh token?** When would a refresh token be unnecessary?

6. **Look at `handle_authorization_code_exchange` line 382 — it checks `auth_code.redirect_uri != redirect_uri`. Why must the redirect URI match?** What attack does this prevent?

7. **The `state` parameter is returned unchanged in the redirect. How does the client use it to prevent CSRF?**

8. **Why is `client_secret` hashed in the database (models.py:109) instead of stored in plain text?** It's not a password — why treat it like one?

## System Design Interview Questions

### 1. "Design an OAuth 2.0 authorization server that supports both web apps and mobile apps"

**What a strong answer covers:**
- Web apps: authorization code flow with client_secret (confidential client)
- Mobile apps: authorization code flow with PKCE (public client — no client_secret)
- SPAs: also PKCE (the implicit flow is deprecated for security reasons)
- Token storage: web apps store tokens server-side, mobile apps use secure storage (Keychain/Keystore)
- Redirect URI validation: strict matching for web, custom URL schemes or app links for mobile
- Rate limiting on token endpoint to prevent credential stuffing

### 2. "A third-party app needs access to user data across multiple microservices. Design the authorization flow."

**What a strong answer covers:**
- Scoped tokens: each scope maps to specific resources/actions
- Audience claim: tokens are scoped to specific services (or use a gateway)
- Token introspection: services validate tokens by calling the auth server (or use RS256 for self-validation)
- Scope consent UI: users see exactly what they're granting
- Token refresh: client refreshes when access token expires, without user interaction
- Revocation propagation: when user revokes access, all services must stop accepting the token

### 3. "Your OAuth authorization codes are being intercepted. How do you design a mitigation?"

**What a strong answer covers:**
- PKCE as the primary mitigation (explain the full flow)
- Why S256 is preferred over plain
- One-time use enforcement for authorization codes
- Short expiry (10 minutes or less)
- Redirect URI exact matching (no wildcard)
- TLS everywhere — codes should never travel over unencrypted connections
- For extra security: DPoP (Demonstration of Proof-of-Possession) tokens
