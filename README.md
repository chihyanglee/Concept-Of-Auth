# Concept-Of-Auth

Personal learning project for deeply understanding authentication and authorization. Built with Flask + SQLAlchemy.

## Quick Start

```bash
cd auth-server
uv sync
uv run python app.py
```

Server runs at `http://localhost:5000`. Swagger UI at `http://localhost:5000/api/docs`.

Default credentials: `admin` / `admin123`
Demo OAuth client: `demo-client` / `demo-secret` (redirect: `http://localhost:3000/callback`)

## Running All Services

To run the full OAuth demo (auth server + client app + resource API):

```bash
./start-all.sh
```

Then open http://localhost:5001 in your browser and click "Login with Auth Server."

| Service | Port | Role |
|---------|------|------|
| Auth Server | 5000 | Authorization server — issues tokens, manages users |
| Task Client App | 5001 | OAuth client — web UI that uses OAuth to authenticate |
| Task Resource API | 5002 | Resource server — validates tokens, serves protected data |

## Learning Roadmap

Read these in order. Each doc covers theory, maps it to this codebase, then tests your understanding with quizzes and system design interview questions.

| # | Doc | What You'll Learn |
|---|-----|-------------------|
| 1 | [Authentication Basics](docs/01-authentication-basics.md) | AuthN vs AuthZ, password hashing, sessions vs tokens, logout via blocklisting |
| 2 | [JWT Deep Dive](docs/02-jwt-deep-dive.md) | Token structure, signing algorithms, access vs refresh vs ID tokens, revocation |
| 3 | [OAuth 2.0 Flows](docs/03-oauth2-flows.md) | Delegated authorization, authorization code flow, client credentials, PKCE |
| 4 | [OpenID Connect](docs/04-openid-connect.md) | Identity layer on OAuth, ID tokens, userinfo, scopes, nonce |
| 5 | [RBAC & Authorization](docs/05-rbac-and-authorization.md) | Roles vs permissions vs scopes, token claims, decorator-based enforcement |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Flask App (app.py)                │
│                                                     │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐  │
│  │  auth_bp    │ │  oauth_bp    │ │  admin_bp    │  │
│  │  /auth/*    │ │  /oauth/*    │ │  /admin/*    │  │
│  │  routes.py  │ │oauth_routes.py│ │admin_routes.py│ │
│  └──────┬──────┘ └──────┬───────┘ └──────┬───────┘  │
│         │               │                │          │
│         └───────────┬───┘────────────────┘          │
│                     │                               │
│              ┌──────┴──────┐                        │
│              │ jwt_utils.py │                        │
│              │ @token_required                       │
│              │ @admin_required                       │
│              │ @scope_required                       │
│              └──────┬──────┘                        │
│                     │                               │
│              ┌──────┴──────┐                        │
│              │  models.py  │                        │
│              │  User, Client                        │
│              │  AuthorizationCode                   │
│              │  TokenBlocklist                      │
│              │  UserSession                         │
│              └──────┬──────┘                        │
│                     │                               │
│              ┌──────┴──────┐                        │
│              │  SQLite DB  │                        │
│              └─────────────┘                        │
└─────────────────────────────────────────────────────┘
```

## Project Structure

```
auth-server/
├── app.py              # Entry point, config, blueprint registration
├── database.py         # SQLAlchemy instance
├── models.py           # User, Client, AuthorizationCode, TokenBlocklist, UserSession
├── jwt_utils.py        # Token creation/validation, auth decorators
├── routes.py           # /auth endpoints (register, login, logout, refresh)
├── oauth_routes.py     # /oauth endpoints (authorize, token, userinfo, introspect, revoke)
├── admin_routes.py     # /admin endpoints (user/client/session management)
├── swagger_config.py   # OpenAPI/Swagger UI setup
├── demo.py             # Interactive demo script for all flows
└── pyproject.toml      # Dependencies and tool config
```
