# OAuth Client Services Design

## Goal
Build 2 services that consume the existing auth server to demonstrate all OAuth 2.0 and OIDC flows in practice.

## Architecture

```
┌────────────────┐     OAuth 2.0 / OIDC      ┌─────────────────┐
│  Task Client   │◄──────────────────────────►│   Auth Server   │
│  (port 5001)   │  Authorization Code+PKCE   │   (port 5000)   │
│                │  ID Token, UserInfo        │   (existing)    │
│  Flask web app │  Token Revocation          └─────────────────┘
│  with UI       │
│                │     Bearer token            ┌─────────────────┐
│                │────────────────────────────►│ Task Resource   │
│                │     API calls               │ API (port 5002) │
└────────────────┘                             │                 │
                                               │ JWT validation  │
                                               │ Scope enforcement│
                                               │ Token introspect│
                                               │ Client creds    │
                                               └─────────────────┘
```

## Task Client App (port 5001)

Flask web app with browser UI.

**Routes:**
- GET / — landing page with "Login with Auth Server" button
- GET /callback — OAuth redirect handler, exchanges code for tokens
- GET /dashboard — user info (from ID token) + task list (from Resource API)
- POST /tasks — create task via Resource API
- POST /logout — revoke tokens, clear session

**Auth flows demonstrated:**
- Authorization Code + PKCE
- Token refresh
- ID token consumption
- UserInfo endpoint
- Token revocation on logout

**Tech:** Flask, requests, server-side session. Runs on port 5001.

## Task Resource API (port 5002)

Flask REST API with JWT validation.

**Endpoints:**
- GET /tasks — list user's tasks (read scope)
- POST /tasks — create task (write scope)
- PUT /tasks/<id> — update task (write scope)
- DELETE /tasks/<id> — delete task (write scope)
- POST /tasks/cleanup — client credentials flow (service-to-service)

**Auth flows demonstrated:**
- JWT self-validation (verify signature with shared secret)
- Token introspection via /oauth/introspect
- Scope-based access control
- Client credentials flow (cleanup endpoint)

**Tech:** Flask, SQLite (separate DB), PyJWT. Runs on port 5002.

## Conventions
- All code heavily commented to explain auth concepts
- Each service is a separate directory with its own pyproject.toml
- Uses uv for package management, mise for tooling
- Minimal business logic — auth concepts stay front and center
