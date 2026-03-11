# RBAC & Authorization

## Concept

**Authorization** is about answering "What is this user allowed to do?" after authentication has already answered "Who is this user?"

There are several models for authorization:

**ACL (Access Control List)** — each resource has a list of who can access it. Simple but doesn't scale: adding a new user means updating every resource's list.

**RBAC (Role-Based Access Control)** — users are assigned roles, roles have permissions. This project uses RBAC. Instead of checking "can user #5 access /admin/users?", you check "does user #5 have the admin role?"

**ABAC (Attribute-Based Access Control)** — decisions based on attributes of the user, resource, and environment (e.g., "users in the engineering department can access this repo during business hours"). More flexible than RBAC but more complex.

**ReBAC (Relationship-Based Access Control)** — decisions based on relationships between entities (e.g., "user can edit this document because they're a member of the team that owns it"). Used by Google Zanzibar (powers Google Drive permissions).

This project implements **RBAC + scope-based permissions**:
- **Roles** (admin, user) control access to administrative functions
- **Scopes** (read, write, openid, profile) control what OAuth clients can do on behalf of users

## How It Works

### Roles vs Scopes

| | Roles | Scopes |
|---|---|---|
| **Assigned to** | Users | Tokens (granted during OAuth consent) |
| **Represent** | Who the user is | What the client can do |
| **Example** | "This user is an admin" | "This app can read and write on behalf of the user" |
| **Checked by** | `@admin_required` | `@scope_required` |
| **Set when** | User creation or admin update | Login (default scopes) or OAuth consent |

**Key insight:** A user might have admin role but grant a third-party app only `read` scope. The app can only read, even though the user could do more. Scopes limit delegation — they don't expand a user's own permissions.

### The Decorator Chain

Authorization in this project is enforced through a chain of decorators:

```python
@admin_bp.route('/users', methods=['GET'])
@token_required        # Step 1: Is the request authenticated?
@admin_required        # Step 2: Does the user have admin role?
def list_users():      # Step 3: Execute if both checks pass
    ...
```

**Execution order matters:** Decorators execute bottom-up in definition but top-down at runtime. `@token_required` runs first (extracts and validates the JWT, populates `request.current_user`), then `@admin_required` runs (checks the role from `request.current_user`).

If you reverse them, `@admin_required` would run before `request.current_user` exists and fail.

### Where Authorization Data Lives

```
┌─────────────┐         ┌──────────────────────────┐
│  Database   │         │    JWT Access Token       │
│             │         │                           │
│  User.role  │────────>│  "role": "admin"          │
│             │  embed  │  "scopes": ["read","write"]│
│             │  at     │  "username": "admin"       │
│             │  login  │                           │
└─────────────┘         └──────────────────────────┘
                                    │
                                    │ sent with
                                    │ every request
                                    ▼
                        ┌──────────────────────────┐
                        │  request.current_user     │
                        │                           │
                        │  Populated by             │
                        │  @token_required          │
                        │  from JWT claims          │
                        └──────────────────────────┘
                                    │
                                    │ checked by
                                    ▼
                        ┌──────────────────────────┐
                        │  @admin_required          │
                        │  @scope_required          │
                        │                           │
                        │  Return 403 if            │
                        │  insufficient             │
                        └──────────────────────────┘
```

The role is read from the database at login time and embedded in the JWT. Until the token expires or is refreshed, the role in the token might be stale.

### 403 vs 401

- **401 Unauthorized** — "I don't know who you are" (authentication failure). Missing or invalid token.
- **403 Forbidden** — "I know who you are, but you can't do this" (authorization failure). Valid token but insufficient role or scopes.

Despite `401` being named "Unauthorized," it actually means "Unauthenticated." The naming is a historical mistake in the HTTP spec.

## In This Codebase

### token_required decorator
- `jwt_utils.py:156-194`:
  - Extracts Bearer token from Authorization header (lines 168-173)
  - Verifies token via `verify_token()` (line 179)
  - Populates `request.current_user` dict with: id, username, role, scopes, client_id (lines 184-190)
  - Returns 401 if no token or invalid token

### admin_required decorator
- `jwt_utils.py:196-212`:
  - Checks `request.current_user['role'] != 'admin'` (line 207)
  - Returns 403 "Admin privileges required" if not admin
  - Must always be used after `@token_required` (needs `request.current_user` to exist)

### scope_required decorator
- `jwt_utils.py:214-243`:
  - Takes a list of required scopes as parameter (line 214)
  - Uses `all(scope in user_scopes for scope in required_scopes)` (line 233)
  - Returns 403 with both required and actual scopes in the error response (lines 234-238) — useful for debugging
  - Example usage: `@scope_required(['read', 'write'])` would require both scopes

### Decorator stacking in admin routes
- `admin_routes.py:19-21` — `list_users()`:
  ```python
  @token_required     # First: authenticate
  @admin_required     # Then: check role
  ```
- This pattern is consistent across all admin endpoints (list_users, get_user, update_user_role, list_clients, etc.)

### Role management
- `models.py:31` — User.role defaults to `'user'`
- `admin_routes.py:78-138` — `update_user_role()`: admin can change roles to 'user' or 'admin'
  - Validates role is one of the allowed values (line 111)
  - Logs the change with old and new role (line 126)

### Default scopes on login
- `routes.py:185` — direct login grants `['read', 'write']` scopes by default
- OAuth flow: scopes are determined by user consent in the authorization endpoint

### Token claims carrying authorization
- `jwt_utils.py:47-52` — access token payload includes `role`, `scopes`, `client_id`
- These claims are what the decorators check — no database query needed per request

## Quiz

1. **What's the difference between RBAC and ABAC?** Give an example of an authorization rule that RBAC can't express but ABAC can.

2. **Why does `@admin_required` return 403, not 401?** What's the semantic difference? When would you use each?

3. **If you stack decorators as `@admin_required` then `@token_required` (reversed), what happens?** Why does order matter?

4. **A user has role `admin` but an OAuth app only requested `read` scope. Can the app access `POST /admin/users`?** Trace through the decorator chain.

5. **The `scope_required` decorator uses `all()` — it requires ALL listed scopes. When would you want `any()` instead?** What's the security trade-off?

6. **Role changes in the database don't take effect immediately. Why?** What's the maximum delay with the current configuration? How would you make it immediate?

7. **Why does the error response from `scope_required` include both `required_scopes` and `user_scopes`?** Is this safe to do in production? What information might it leak?

8. **This project has two roles: user and admin. Design how you'd extend it to support a `moderator` role that can manage users but not clients.**

## System Design Interview Questions

### 1. "Design an authorization system for a multi-tenant SaaS application where users can have different roles in different organizations"

**What a strong answer covers:**
- Multi-tenancy: role assignments are per-organization, not global
- Data model: User → Membership (user_id, org_id, role) → Organization
- Token claims: must include org context (which org is the user acting in?)
- Token structure: either include all org memberships (bloated) or require org selection at login
- API design: org ID in URL path or header, validated against token claims
- Permission resolution: role → permissions mapping, checked per request
- Cross-tenant access: explicit deny by default, audit logging

### 2. "You're building a document sharing system like Google Docs. How do you design the permission model?"

**What a strong answer covers:**
- ReBAC over RBAC: permissions are based on relationships (owner, editor, viewer)
- Hierarchical permissions: folder permissions cascade to documents
- Sharing: creating relationship entries (document_id, user_id, role)
- Public links: special "anyone" relationship
- Permission checks: traverse the relationship graph (or precompute)
- Scale: Google Zanzibar-style — store relationships as tuples, use caching
- Why RBAC alone fails: you can't have a global "editor" role — it's per-document

### 3. "An engineer accidentally gave all users admin access through a bug. How do you design the system to prevent and detect this?"

**What a strong answer covers:**
- Prevention: role changes require admin token (like this project's `@admin_required`)
- Audit trail: log every role change with who changed it, old value, new value (like admin_routes.py:126)
- Alerting: anomaly detection on bulk role changes
- Blast radius limiting: admin can't elevate above their own role
- Recovery: token expiry limits damage window (15 min in this project)
- Defense in depth: critical operations require re-authentication even with admin role
- Testing: integration tests that verify authorization on every protected endpoint
