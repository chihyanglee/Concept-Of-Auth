# Authentication Basics

## Concept

**Authentication (AuthN)** answers "Who are you?" — verifying that a user is who they claim to be.
**Authorization (AuthZ)** answers "What can you do?" — determining what an authenticated user is allowed to access.

These are separate concerns. You must authenticate before you can authorize. This project handles both: AuthN happens in `routes.py` (login/register), while AuthZ happens through JWT claims and decorators in `jwt_utils.py`.

## How It Works

### Password Hashing

Passwords are never stored in plain text. Instead, a one-way hash function transforms the password into a fixed-length string that cannot be reversed.

**Why not encryption?** Encryption is reversible — if an attacker gets the key, they get all passwords. Hashing is one-way: even with the hash, you can't recover the original password.

**Why not MD5 or SHA-256?** These are fast by design, which makes brute-force attacks feasible. Password hashing algorithms like bcrypt, scrypt, or PBKDF2 are intentionally slow, making brute-force impractical. They also include a unique **salt** per password, so identical passwords produce different hashes.

**The flow:**
1. User registers → password is hashed with a random salt → hash is stored
2. User logs in → submitted password is hashed with the same salt → compared to stored hash
3. If hashes match → user is authenticated

### Sessions vs Tokens

There are two main approaches to maintaining authenticated state:

**Server-side sessions:**
- Server stores session data (user ID, permissions) in memory or a database
- Client gets a session ID cookie
- Every request: client sends cookie → server looks up session → knows who the user is
- Problem: server must store state for every active user (doesn't scale horizontally without shared storage)

**Token-based (what this project uses):**
- Server creates a signed token containing user identity and permissions
- Client stores the token and sends it with every request
- Server validates the token's signature — no lookup needed
- **Stateless**: any server instance can validate the token independently
- Trade-off: you can't invalidate a token without maintaining a blocklist (which reintroduces some state)

### Token Blocklisting (Logout)

JWTs are stateless by design — once issued, they're valid until expiry. So how do you logout?

This project uses a **blocklist**: when a user logs out, the token's unique ID (JTI) is added to the `token_blocklist` table. On every request, the server checks if the token's JTI is blocklisted before granting access.

This is a pragmatic compromise between pure statelessness and the need for logout/revocation. The blocklist is much smaller than a full session store — it only contains revoked tokens, and entries can be cleaned up after the token's natural expiry.

## In This Codebase

### Password hashing
- `models.py:45` — `generate_password_hash(password)` in User.__init__ hashes the password on registration
- `models.py:58` — `check_password_hash()` in User.check_password verifies during login
- Werkzeug defaults to PBKDF2 with a random salt

### Login flow
- `routes.py:107-208` — login endpoint:
  1. Receives username + password
  2. Looks up user by username (`line 157`)
  3. Verifies password hash (`line 159`)
  4. Creates a UserSession for tracking (`lines 168-177`)
  5. Generates access token (15 min) + refresh token (7 days) (`lines 181-191`)
  6. Returns both tokens to the client

### Token creation
- `jwt_utils.py:15-54` — `create_access_token()` builds the JWT payload with standard claims (iss, sub, exp, iat, jti) plus custom claims (username, role, scopes)
- `jwt_utils.py:56-83` — `create_refresh_token()` is intentionally minimal — only identity, no permissions

### Logout and blocklisting
- `routes.py:210-294` — logout endpoint revokes the access token (and optionally the refresh token)
- `jwt_utils.py:245-290` — `revoke_token()` decodes the token, extracts the JTI, and adds it to TokenBlocklist
- `jwt_utils.py:142` — `verify_token()` checks `TokenBlocklist.is_token_blocked(jti)` on every validation
- `models.py:254-265` — `TokenBlocklist.is_token_blocked()` performs the DB lookup

### Token expiry configuration
- `app.py:14` — access tokens: 15 minutes
- `app.py:15` — refresh tokens: 7 days
- Short-lived access tokens limit the damage window if a token is stolen

## Quiz

1. **What's the difference between authentication and authorization?** Can you point to where each happens in this codebase?

2. **Why does the User model store `password_hash` instead of `password`?** What would happen if the database were compromised and passwords were stored in plain text?

3. **Why does `create_refresh_token` contain fewer claims than `create_access_token`?** What's the security reasoning?

4. **If you remove the TokenBlocklist check from `verify_token`, what breaks?** What can a logged-out user still do?

5. **Why does the login endpoint return both an access token AND a refresh token?** Why not just make the access token last longer?

6. **The blocklist grows over time. When is it safe to delete entries?** Look at `TokenBlocklist.is_expired()` — what does it check?

7. **What's the difference between a session ID cookie approach and the JWT approach used here?** Name one advantage and one disadvantage of each.

## System Design Interview Questions

### 1. "Design an authentication system for a web application with 10M users"

**What a strong answer covers:**
- Password storage: hashing algorithm choice (bcrypt/argon2), salt handling
- Token strategy: short-lived access + long-lived refresh tokens
- Logout mechanism: token blocklist vs short expiry trade-off
- Session storage: where to store blocklist at scale (Redis vs DB)
- Rate limiting on login endpoints to prevent brute force
- Account lockout policies
- How horizontal scaling works with stateless JWT vs sticky sessions

### 2. "A user reports their account was compromised. Walk through your incident response from an auth system perspective."

**What a strong answer covers:**
- Immediate: revoke all active tokens for the user (force logout from all devices)
- Force password reset
- Check login history (UserSession table — IP addresses, device info)
- Consider: was the password stolen (phishing) or the token stolen (XSS/network)?
- If token stolen: how short-lived tokens limit the blast radius
- Audit trail: which endpoints were accessed with the compromised credentials

### 3. "How would you migrate from session-based auth to token-based auth without downtime?"

**What a strong answer covers:**
- Dual-mode: accept both session cookies and Bearer tokens during migration
- New login endpoint issues JWTs while old endpoint still works
- Client-by-client migration plan
- Blocklist strategy for the transition period
- Rollback plan if something goes wrong
- Monitoring: track which auth method each request uses
