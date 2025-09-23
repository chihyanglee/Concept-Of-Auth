# Auth Server - Educational Implementation

A comprehensive authentication and authorization server built with Flask to demonstrate OAuth 2.0, OpenID Connect (OIDC), and Role-Based Access Control (RBAC) concepts.

## Features

### Core Authentication

- User registration and login
- JWT-based session management
- Secure password hashing
- Token-based logout with blocklisting

### OAuth 2.0 & OIDC

- Authorization Code flow with PKCE
- Client Credentials flow
- Token refresh mechanism
- UserInfo endpoint
- Token introspection and revocation

### Authorization

- Role-based access control (RBAC)
- Scope-based permissions
- Token claims for downstream services

## Quick Start

1. Install dependencies:

```bash
uv sync
```

2. Run the server:

```bash
uv run python app.py
```

3. Access Swagger UI at: http://localhost:5000/api/docs

## Learning Concepts Covered

- **Authentication vs Authorization**: Clear separation of identity verification and permission checking
- **JWT Structure**: Understanding access tokens, refresh tokens, and ID tokens
- **OAuth 2.0 Flows**: Authorization Code, Client Credentials, and PKCE
- **OpenID Connect**: Identity layer on top of OAuth 2.0
- **Security Best Practices**: Token expiration, revocation, and secure storage
- **RBAC Implementation**: Role and permission management in tokens


