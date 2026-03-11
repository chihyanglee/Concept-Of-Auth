# OpenID Connect (OIDC)

## Concept

**The problem OIDC solves:** OAuth 2.0 handles authorization (granting access to resources) but says nothing about authentication (proving who the user is). A client that receives an OAuth access token knows it can access certain resources, but doesn't reliably know *who* the user is.

**OpenID Connect** is a thin identity layer built on top of OAuth 2.0. It adds:
1. **ID Token** — a JWT that tells the client who the user is
2. **UserInfo Endpoint** — an API to fetch user profile information
3. **Standard Scopes** — `openid`, `profile`, `email` with defined meanings

OIDC turns OAuth from "this token can read your data" into "this token can read your data, and by the way, the user is Simon with email simon@example.com."

## How It Works

### ID Token vs Access Token

| | ID Token | Access Token |
|---|---|---|
| **Purpose** | Prove the user's identity to the client | Access protected resources |
| **Audience** | The client application | The resource server |
| **Contains** | User profile (name, email) | User permissions (role, scopes) |
| **Used for** | Client-side identity verification | API calls |
| **Sent to** | Never sent to APIs | Sent as Bearer token to APIs |
| **Analogy** | A passport (proves who you are) | A key card (grants access to rooms) |

A common mistake: using the ID token as an access token. The ID token is meant to be consumed by the client — it should never be sent to a resource server.

### Standard OIDC Scopes

| Scope | What the client gets |
|-------|---------------------|
| `openid` | Required. Triggers OIDC flow. Client receives an ID token. |
| `profile` | User's name, username, updated_at |
| `email` | User's email address and whether it's verified |

The `openid` scope is the switch: if a client requests it, the auth server knows to include an ID token in the response. Without `openid`, it's a pure OAuth 2.0 flow.

### Nonce (Replay Protection)

The `nonce` is a random value the client generates and includes in the authorization request. The auth server echoes it back inside the ID token. The client then verifies the nonce matches.

**Why?** It prevents **replay attacks**: an attacker can't re-use a captured ID token in a different session because the nonce won't match what the client expects.

This is similar to `state` (which protects the authorization flow) but `nonce` protects the ID token specifically.

### UserInfo Endpoint

An alternative to reading claims from the ID token. The client sends an access token to `/oauth/userinfo` and gets back the user's profile.

**When to use which:**
- **ID Token**: for immediate identity verification at login time (no extra API call needed)
- **UserInfo Endpoint**: for fetching up-to-date profile info later (the ID token might have stale data)

## In This Codebase

### ID token creation
- `jwt_utils.py:85-120` — `create_id_token()`:
  - Standard OIDC claims: `iss`, `sub`, `aud`, `exp`, `iat` (lines 104-110)
  - Profile claims: `preferred_username`, `email`, `email_verified` (lines 112-114)
  - `nonce` included if the client provided one (lines 117-118)
  - 1-hour expiry — longer than access token because it's not used for API access (line 108)
  - `type: 'id_token'` distinguishes it from access/refresh tokens (line 111)

### When the ID token is issued
- `oauth_routes.py:431-437` — in `handle_authorization_code_exchange()`:
  - Only issued when `'openid' in granted_scopes`
  - Included in the token response alongside access_token and refresh_token
  - The `openid` scope is the trigger — without it, no ID token

### Scope handling in authorization
- `oauth_routes.py:162-166` — in the authorize endpoint:
  - Requested scopes are filtered against the client's allowed scopes
  - Only scopes the client is registered for are granted
  - Example: demo client allows `read write openid profile` (app.py:60)

### UserInfo endpoint
- `oauth_routes.py:538-619` — `/oauth/userinfo`:
  - Requires a valid access token (lines 563-584)
  - Always returns `sub` and `preferred_username` (lines 597-599)
  - Conditionally adds claims based on scopes:
    - `profile` scope → `name`, `updated_at` (lines 604-608)
    - `email` scope → `email`, `email_verified` (lines 610-614)
  - Always includes `role` as a custom claim (line 617)

## Quiz

1. **What problem does OIDC solve that OAuth 2.0 alone doesn't?** Can you authenticate a user with just an OAuth 2.0 access token?

2. **When the `openid` scope is not requested, what changes in the token response?** Look at `oauth_routes.py:431-437`.

3. **Why does the ID token have a longer expiry (1 hour) than the access token (15 minutes)?** Wouldn't a shorter expiry be more secure?

4. **What's the difference between getting user info from the ID token vs calling `/oauth/userinfo`?** When would you prefer one over the other?

5. **How does the `nonce` prevent replay attacks?** Walk through the scenario: what happens if an attacker intercepts an ID token and tries to use it in a different session?

6. **Look at the userinfo endpoint — it returns different data depending on scopes. Why not just return everything?** What's the privacy implication?

7. **The ID token contains `email: f"{username}@example.com"` — this is a mock. In a real system, where would this data come from, and what additional verification would be needed?**

## System Design Interview Questions

### 1. "Design a Single Sign-On (SSO) system for an organization with 20 internal web applications"

**What a strong answer covers:**
- Central OIDC provider (identity provider / IdP)
- Each app is an OIDC client with its own client_id
- Authorization code flow with PKCE for each app
- ID token for user identity, access token for API calls
- Session management: user logs in once, IdP session persists
- Single logout: revoking the IdP session logs out of all apps
- Token lifetimes: short access tokens, session cookies on the IdP
- User provisioning: SCIM or just-in-time provisioning from ID token claims

### 2. "How do you handle identity federation — letting users log in with Google, GitHub, or corporate SAML?"

**What a strong answer covers:**
- Your auth server becomes a relying party (client) to external IdPs
- Protocol translation: receive OIDC/SAML from external IdP, issue your own tokens
- Account linking: map external identity (Google sub) to internal user ID
- First-time login: auto-create user from ID token claims (JIT provisioning)
- Trust: validating ID tokens from external providers (verify signature with their public key)
- Scope mapping: external scopes may not match your internal permission model

### 3. "A client application is using ID tokens as access tokens to call APIs. What are the security risks?"

**What a strong answer covers:**
- Audience mismatch: ID token's `aud` is the client, not the API
- No scope enforcement: ID tokens don't carry authorization scopes
- Token confusion: resource server can't distinguish between ID and access tokens
- Replay risk: ID tokens may have longer expiry than access tokens
- Fix: always use access tokens for API calls, ID tokens for client-side identity only
- The resource server should reject tokens where `type != 'access'` (like this project does in `verify_token`)
