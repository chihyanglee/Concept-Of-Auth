# Auth Server API Documentation

## Overview

This educational authentication server demonstrates comprehensive authentication and authorization concepts including OAuth 2.0, OpenID Connect (OIDC), and Role-Based Access Control (RBAC).

## Base URL

```
http://localhost:5000
```

## Interactive Documentation

Visit `http://localhost:5000/api/docs` for interactive Swagger UI documentation.

## Authentication Concepts Covered

### 1. Core Authentication (Phase 1)

- **User Registration**: Secure account creation with password hashing
- **User Login**: Credential verification and JWT token generation
- **User Logout**: Secure logout with token revocation
- **Token Refresh**: Long-lived session management

### 2. OAuth 2.0 & OpenID Connect (Phase 2)

- **Authorization Code Flow**: Standard OAuth 2.0 flow with PKCE
- **Token Exchange**: Authorization code to access token conversion
- **UserInfo Endpoint**: OIDC-compliant user information retrieval
- **Token Introspection**: Token validation and metadata retrieval
- **Token Revocation**: Secure token invalidation

### 3. Client Credentials Flow (Phase 3)

- **Machine-to-Machine**: Service-to-service authentication
- **Client Authentication**: Application-level access tokens

### 4. Role-Based Access Control (Phase 4)

- **Role Management**: Dynamic user role assignment
- **Admin Endpoints**: Administrative functionality
- **Permission Enforcement**: Scope and role-based access control

## API Endpoints

### Authentication Endpoints (`/auth`)

#### POST `/auth/register`

Register a new user account.

**Request Body:**

```json
{
  "username": "testuser",
  "password": "password123",
  "role": "user"
}
```

**Response:**

```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "testuser",
    "role": "user",
    "created_at": "2024-01-01T00:00:00"
  }
}
```

#### POST `/auth/login`

Authenticate user and receive JWT tokens.

**Request Body:**

```json
{
  "username": "testuser",
  "password": "password123"
}
```

**Response:**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "username": "testuser",
    "role": "user"
  }
}
```

#### POST `/auth/logout`

Logout user and revoke tokens.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### POST `/auth/refresh`

Refresh access token using refresh token.

**Request Body:**

```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### GET `/auth/me`

Get current user information.

**Headers:**

```
Authorization: Bearer <access_token>
```

### OAuth 2.0 Endpoints (`/oauth`)

#### GET `/oauth/authorize`

Initiate OAuth 2.0 authorization flow.

**Query Parameters:**

- `response_type`: "code"
- `client_id`: OAuth client identifier
- `redirect_uri`: Callback URL
- `scope`: Space-separated scopes
- `state`: CSRF protection token
- `code_challenge`: PKCE code challenge (optional)
- `code_challenge_method`: PKCE method (S256 or plain)

#### POST `/oauth/token`

Exchange authorization code for tokens or refresh tokens.

**Authorization Code Exchange:**

```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code",
  "redirect_uri": "http://localhost:3000/callback",
  "client_id": "demo-client",
  "client_secret": "demo-secret",
  "code_verifier": "pkce_code_verifier"
}
```

**Refresh Token Exchange:**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh_token",
  "client_id": "demo-client",
  "client_secret": "demo-secret"
}
```

**Client Credentials:**

```json
{
  "grant_type": "client_credentials",
  "client_id": "demo-client",
  "client_secret": "demo-secret",
  "scope": "read write"
}
```

#### GET `/oauth/userinfo`

Get user information (OIDC UserInfo endpoint).

**Headers:**

```
Authorization: Bearer <access_token>
```

#### POST `/oauth/introspect`

Introspect token for validation.

**Request Body:**

```json
{
  "token": "token_to_introspect",
  "token_type_hint": "access"
}
```

#### POST `/oauth/revoke`

Revoke a token.

**Request Body:**

```json
{
  "token": "token_to_revoke",
  "token_type_hint": "access"
}
```

### Admin Endpoints (`/admin`)

All admin endpoints require admin role.

#### GET `/admin/users`

List all users.

#### GET `/admin/users/{user_id}`

Get specific user information.

#### PUT `/admin/users/{user_id}/role`

Update user role.

**Request Body:**

```json
{
  "role": "admin"
}
```

#### GET `/admin/clients`

List all OAuth clients.

#### POST `/admin/clients`

Create new OAuth client.

**Request Body:**

```json
{
  "client_id": "new-client",
  "client_secret": "secret123",
  "client_name": "New Application",
  "redirect_uris": "http://localhost:3000/callback",
  "scopes": "read write openid profile",
  "client_type": "confidential"
}
```

#### GET `/admin/sessions`

List all active user sessions.

#### POST `/admin/sessions/{user_id}/revoke-all`

Revoke all sessions for a user.

#### GET `/admin/blocklist`

List blocked tokens.

#### GET `/admin/stats`

Get system statistics.

## Default Credentials

### Admin User

- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `admin`

### Demo OAuth Client

- **Client ID**: `demo-client`
- **Client Secret**: `demo-secret`
- **Redirect URI**: `http://localhost:3000/callback`
- **Scopes**: `read write openid profile`

## JWT Token Structure

### Access Token Claims

```json
{
  "iss": "auth-server",
  "sub": "user_id",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "unique_token_id",
  "type": "access",
  "username": "testuser",
  "role": "user",
  "scopes": ["read", "write"],
  "client_id": "demo-client"
}
```

### Refresh Token Claims

```json
{
  "iss": "auth-server",
  "sub": "user_id",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "unique_token_id",
  "type": "refresh"
}
```

### ID Token Claims (OIDC)

```json
{
  "iss": "auth-server",
  "sub": "user_id",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "unique_token_id",
  "type": "id_token",
  "preferred_username": "testuser",
  "email": "testuser@example.com",
  "email_verified": true,
  "nonce": "optional_nonce"
}
```

## Security Features

### PKCE (Proof Key for Code Exchange)

- Prevents authorization code interception attacks
- Uses SHA256 code challenge method
- Code verifier must be provided during token exchange

### Token Revocation

- Tokens are added to blocklist when revoked
- Blocklist is checked during token validation
- Supports both access and refresh token revocation

### Session Management

- Tracks active user sessions
- Supports concurrent login detection
- Enables "logout from all devices" functionality

### Role-Based Access Control

- Dynamic role assignment
- Admin-only endpoints
- Scope-based permissions in tokens

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "error_code",
  "error_description": "Human readable error description"
}
```

Common error codes:

- `invalid_request`: Missing or invalid parameters
- `invalid_client`: Invalid client credentials
- `invalid_grant`: Invalid authorization code or refresh token
- `access_denied`: User denied authorization
- `unsupported_grant_type`: Unsupported OAuth grant type
- `invalid_token`: Invalid or expired token
- `insufficient_scope`: Missing required scopes

## Running the Server

1. Install dependencies:

```bash
uv sync
```

2. Start the server:

```bash
uv run python app.py
```

3. Or use the startup script:

```bash
./start.sh
```

4. Run the demo script:

```bash
uv run python demo.py
```

## Learning Resources

This implementation demonstrates:

- **Authentication vs Authorization**: Clear separation of concepts
- **JWT Structure**: Token-based authentication
- **OAuth 2.0 Flows**: Authorization Code, Client Credentials
- **OpenID Connect**: Identity layer on OAuth 2.0
- **PKCE**: Enhanced security for OAuth flows
- **RBAC**: Role and permission management
- **Token Security**: Revocation, introspection, expiration
- **Session Management**: Multi-device login handling
