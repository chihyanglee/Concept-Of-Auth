# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Educational authentication/authorization server implementing OAuth 2.0, OpenID Connect (OIDC), and Role-Based Access Control (RBAC). Built with Flask + SQLAlchemy, using SQLite for storage.

## Toolchain

- **mise** manages tool versions (Python, uv) — see `mise.toml`
- **uv** manages Python packages — each service has its own `pyproject.toml` and `uv.lock`
- **Python 3.14** — pinned in `.python-version` and `mise.toml`

## Commands

```bash
# Set up toolchain (installs Python + uv via mise)
mise install

# Start all three services (auth server + client app + resource API)
./start-all.sh

# Or run a single service
cd auth-server && uv run python app.py        # port 5000
cd task-client-app && uv run python app.py    # port 5001
cd task-resource-api && uv run python app.py  # port 5002

# Install dependencies for a service
cd auth-server && uv sync

# Run tests
cd auth-server && uv run pytest

# Format code
cd auth-server && uv run black .

# Lint
cd auth-server && uv run flake8
```

## Code Style

- Formatter: Black (line-length 88, target Python 3.14)
- Linter: Flake8 (ignores E203, W503)

## Architecture

All application code lives in `auth-server/`. There is no nested package structure — all modules are top-level files.

**Entry point:** `app.py` — creates Flask app, registers blueprints, initializes DB with default admin user and demo OAuth client.

**Three Flask blueprints handle all routing:**

| Blueprint | File | Prefix | Purpose |
|-----------|------|--------|---------|
| `auth_bp` | `routes.py` | `/auth` | Registration, login/logout, token refresh, user profile |
| `oauth_bp` | `oauth_routes.py` | `/oauth` | Authorization code flow (with PKCE), client credentials, token introspection/revocation, OIDC userinfo |
| `admin_bp` | `admin_routes.py` | `/admin` | User/client/session management, system stats (admin-only) |

**Supporting modules:**

- `models.py` — SQLAlchemy models: User, Client, AuthorizationCode, TokenBlocklist, UserSession
- `jwt_utils.py` — JWT creation/validation, decorators (`@token_required`, `@admin_required`, `@scope_required`)
- `database.py` — SQLAlchemy instance (`db`)
- `swagger_config.py` — Flasgger/OpenAPI configuration

**Key patterns:**
- Protected routes use decorator chaining: `@token_required` → `@admin_required` → `@scope_required`
- Token revocation uses a JTI blocklist (TokenBlocklist model)
- OAuth authorization code flow supports PKCE (S256 and plain methods)
- JWT access tokens expire in 15 min, refresh tokens in 7 days
- All API responses use `{"message": ...}` for success, `{"error": ...}` for errors

**Swagger UI** is available at `/api/docs` when the server is running.

**Default credentials (created on first run):** admin/admin123, demo OAuth client: demo-client/demo-secret
